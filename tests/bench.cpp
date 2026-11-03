#include "obliterator/handles.hpp"
#include "obliterator/path.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/process.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/wiper.hpp"

#include <fcntl.h>
#include <io.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace obliterator;

struct BenchmarkTimer {
    LARGE_INTEGER freq;
    LARGE_INTEGER start;
    BenchmarkTimer() {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
    }
    double elapsed_ms() const {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        return static_cast<double>(now.QuadPart - start.QuadPart) * 1000.0 /
               static_cast<double>(freq.QuadPart);
    }
};

static double calculate_median(std::vector<double> vals) {
    if (vals.empty()) {
        return 0.0;
    }
    std::sort(vals.begin(), vals.end());
    size_t mid = vals.size() / 2;
    if (vals.size() % 2 == 0) {
        return (vals[mid - 1] + vals[mid]) / 2.0;
    }
    return vals[mid];
}

class TestTreeGenerator {
public:
    static bool generate(const std::wstring& root_path, size_t total_files = 5000, size_t total_mb = 600) {
        std::error_code ec;
        fs::path root(root_path);
        fs::create_directories(root, ec);
        if (ec) {
            std::wcerr << L"Failed to create root directory: " << root_path << L"\n";
            return false;
        }

        const size_t num_large_files = 6;
        const size_t large_file_mb = (total_mb > 100) ? ((total_mb - 50) / num_large_files) : 10;
        const size_t num_small_files = (total_files > num_large_files) ? (total_files - num_large_files) : 100;

        // Generate ~150-200 directories across 8 levels of nesting
        std::vector<fs::path> dirs;
        dirs.push_back(root);

        const size_t max_depth = 8;
        const size_t branches_per_level = 3;

        std::vector<fs::path> current_level = {root};
        for (size_t depth = 1; depth <= max_depth; ++depth) {
            std::vector<fs::path> next_level;
            for (const auto& parent : current_level) {
                for (size_t b = 0; b < branches_per_level; ++b) {
                    fs::path dir = parent / (L"subdir_" + std::to_wstring(depth) + L"_" + std::to_wstring(b));
                    fs::create_directory(dir, ec);
                    dirs.push_back(dir);
                    next_level.push_back(dir);
                    if (dirs.size() >= 200) {
                        break;
                    }
                }
                if (dirs.size() >= 200) {
                    break;
                }
            }
            if (dirs.size() >= 200) {
                break;
            }
            current_level = std::move(next_level);
        }

        const size_t num_dirs = dirs.size();

        // 1. Create small files (50 bytes to 32 KB)
        std::string small_content(1024, 'X');
        for (size_t i = 0; i < small_content.size(); ++i) {
            small_content[i] = static_cast<char>('A' + (i % 26));
        }

        for (size_t i = 0; i < num_small_files; ++i) {
            const auto& dir = dirs[i % num_dirs];
            fs::path file_path = dir / (L"file_" + std::to_wstring(i) + L".dat");
            std::wstring ext_path = FileWiper::ensure_extended_path(file_path.wstring());

            UniqueHandle hFile(CreateFileW(
                ext_path.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            ));

            if (hFile) {
                // Vary sizes: some 256 B, some 1 KB, some 4 KB, some 16 KB
                size_t write_sz = 256;
                if (i % 10 == 0) {
                    write_sz = 16384;
                } else if (i % 5 == 0) {
                    write_sz = 4096;
                } else if (i % 2 == 0) {
                    write_sz = 1024;
                }

                DWORD written = 0;
                while (write_sz > 0) {
                    DWORD chunk = static_cast<DWORD>(std::min(write_sz, small_content.size()));
                    WriteFile(hFile.get(), small_content.data(), chunk, &written, nullptr);
                    write_sz -= written;
                }
            }
        }

        // 2. Create large files (totaling remaining ~550 MB)
        for (size_t i = 0; i < num_large_files; ++i) {
            const auto& dir = dirs[(i * 31) % num_dirs];
            fs::path file_path = dir / (L"large_payload_" + std::to_wstring(i) + L".bin");
            std::wstring ext_path = FileWiper::ensure_extended_path(file_path.wstring());

            UniqueHandle hFile(CreateFileW(
                ext_path.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            ));

            if (hFile) {
                LARGE_INTEGER target_sz{};
                target_sz.QuadPart = static_cast<LONGLONG>(large_file_mb) * 1024LL * 1024LL;
                SetFilePointerEx(hFile.get(), target_sz, nullptr, FILE_BEGIN);
                SetEndOfFile(hFile.get());

                // Write 4 KB of real data at beginning
                LARGE_INTEGER zero{};
                SetFilePointerEx(hFile.get(), zero, nullptr, FILE_BEGIN);
                DWORD written = 0;
                WriteFile(hFile.get(), small_content.data(), static_cast<DWORD>(small_content.size()), &written, nullptr);
            }
        }

        return true;
    }
};

struct RunMetrics {
    double proc_ms{0.0};
    double enum_ms{0.0};
    double del_ms{0.0};
    double reg_ms{0.0};
    double total_ms{0.0};
    size_t files_deleted{0};
    size_t dirs_deleted{0};
    uint64_t bytes_freed{0};
};

static RunMetrics run_single_wipe_benchmark(const std::wstring& target_dir) {
    RunMetrics m;
    BenchmarkTimer total_timer;

    // 1. Process search
    BenchmarkTimer proc_timer;
    auto procs = ProcessManager::find_target_processes(target_dir);
    m.proc_ms = proc_timer.elapsed_ms();

    // 2 & 3. Physical wipe (enumeration + deletion)
    PhysicalWipeReport wipe_report;
    auto wipe_res = FileWiper::wipe_physical_tree(target_dir, wipe_report);
    m.enum_ms = wipe_report.enumeration_ms;
    m.del_ms = wipe_report.deletion_ms;
    m.files_deleted = wipe_report.files_deleted;
    m.dirs_deleted = wipe_report.directories_deleted;
    m.bytes_freed = wipe_report.bytes_freed;

    // 4. Registry search
    BenchmarkTimer reg_timer;
    RegistryCleanReport reg_report;
    Target bench_target;
    bench_target.name = L"BenchmarkTarget";
    bench_target.root_path = target_dir;
    auto reg_res = RegistryCleaner::clean(bench_target, reg_report, true);
    m.reg_ms = reg_timer.elapsed_ms();

    m.total_ms = total_timer.elapsed_ms();
    return m;
}

static void run_wipe_benchmark_suite(const std::wstring& target_dir, size_t iterations = 10) {
    std::wcout << L"Running " << iterations << L"-iteration wipe benchmark...\n";
    std::wcout << L"Target: " << target_dir << L"\n\n";

    std::vector<double> proc_times;
    std::vector<double> enum_times;
    std::vector<double> del_times;
    std::vector<double> reg_times;
    std::vector<double> total_times;

    for (size_t i = 1; i <= iterations; ++i) {
        std::wcout << L"Iteration " << i << L"/" << iterations << L": generating test tree... " << std::flush;
        BenchmarkTimer gen_timer;
        if (!TestTreeGenerator::generate(target_dir, 5000, 600)) {
            std::wcerr << L"Generation failed.\n";
            return;
        }
        std::wcout << L"done in " << std::fixed << std::setprecision(1) << gen_timer.elapsed_ms() << L" ms. Wiping... " << std::flush;

        RunMetrics m = run_single_wipe_benchmark(target_dir);
        proc_times.push_back(m.proc_ms);
        enum_times.push_back(m.enum_ms);
        del_times.push_back(m.del_ms);
        reg_times.push_back(m.reg_ms);
        total_times.push_back(m.total_ms);

        std::wcout << L"done: enum=" << m.enum_ms << L" ms, del=" << m.del_ms
                   << L" ms, total=" << m.total_ms << L" ms (" << m.files_deleted << L" files)\n";
    }

    std::wcout << L"\n======================================================\n";
    std::wcout << L"Wipe Benchmark Summary (Median of " << iterations << L" runs):\n";
    std::wcout << L"======================================================\n";
    std::wcout << L"Process Search:    " << std::fixed << std::setprecision(2) << calculate_median(proc_times) << L" ms\n";
    std::wcout << L"File Enumeration:  " << calculate_median(enum_times) << L" ms\n";
    std::wcout << L"File Deletion:     " << calculate_median(del_times) << L" ms\n";
    std::wcout << L"Registry Scan:     " << calculate_median(reg_times) << L" ms\n";
    std::wcout << L"Total Duration:    " << calculate_median(total_times) << L" ms\n";
    std::wcout << L"======================================================\n\n";
}

static void run_scan_benchmark_suite(size_t iterations = 10) {
    std::wcout << L"Running " << iterations << L"-iteration installed apps scan benchmark (warm cache)...\n";

    // Warm-up run
    auto warmup = UserInterface::enumerate_installed_apps();
    std::wcout << L"Warm-up complete. Detected " << warmup.size() << L" installed apps.\n";

    std::vector<double> scan_times;
    for (size_t i = 1; i <= iterations; ++i) {
        BenchmarkTimer timer;
        auto apps = UserInterface::enumerate_installed_apps();
        double ms = timer.elapsed_ms();
        scan_times.push_back(ms);
        std::wcout << L"Run " << i << L": " << std::fixed << std::setprecision(2) << ms << L" ms (" << apps.size() << L" apps)\n";
    }

    std::wcout << L"\n======================================================\n";
    std::wcout << L"Installed Scan Summary (Median of " << iterations << L" runs):\n";
    std::wcout << L"======================================================\n";
    std::wcout << L"Scan Duration:     " << std::fixed << std::setprecision(2) << calculate_median(scan_times) << L" ms\n";
    std::wcout << L"======================================================\n\n";
}

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    auto priv_res = enable_required_privileges();
    if (!priv_res) {
        std::wcerr << L"Warning: could not assign privileges: " << priv_res.error().message() << L"\n";
    }

    std::wstring mode = L"--all";
    std::wstring target = L"D:\\Projects\\obliterator\\build\\bench_data";

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--generate" && i + 1 < argc) {
            target = argv[++i];
            std::wcout << L"Generating test tree at: " << target << L"\n";
            if (TestTreeGenerator::generate(target, 5000, 600)) {
                std::wcout << L"Successfully generated 5000 files, 600 MB at " << target << L"\n";
                return 0;
            }
            return 1;
        } else if (arg == L"--bench-wipe") {
            mode = L"--wipe";
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                target = argv[++i];
            }
        } else if (arg == L"--bench-scan") {
            mode = L"--scan";
        } else if (arg == L"--all") {
            mode = L"--all";
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                target = argv[++i];
            }
        }
    }

    if (mode == L"--scan") {
        run_scan_benchmark_suite(10);
    } else if (mode == L"--wipe") {
        run_wipe_benchmark_suite(target, 10);
    } else {
        run_scan_benchmark_suite(10);
        run_wipe_benchmark_suite(target, 10);
    }

    return 0;
}
