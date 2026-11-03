#include "obliterator/audit.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <vector>

namespace obliterator {

static std::mutex s_audit_mutex;

std::wstring AuditJournal::get_logs_directory() {
    wchar_t buf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LocalAppData", buf, MAX_PATH) > 0) {
        return std::wstring(buf) + L"\\obliterator\\logs";
    }
    return L"C:\\obliterator\\logs";
}

std::wstring AuditJournal::get_journal_file_path() {
    return get_logs_directory() + L"\\audit.jsonl";
}

static std::wstring get_iso_timestamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t buf[64]{};
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::wstring escape_json(std::wstring_view input) {
    std::wstring out;
    out.reserve(input.size() + 16);
    for (wchar_t c : input) {
        if (c == L'\\') {
            out += L"\\\\";
        } else if (c == L'\"') {
            out += L"\\\"";
        } else if (c == L'\n') {
            out += L"\\n";
        } else if (c == L'\r') {
            out += L"\\r";
        } else if (c == L'\t') {
            out += L"\\t";
        } else {
            out += c;
        }
    }
    return out;
}

void AuditJournal::check_and_rotate(size_t max_bytes, size_t max_backups) {
    namespace fs = std::filesystem;
    const std::wstring log_path = get_journal_file_path();
    std::error_code ec;
    if (!fs::exists(log_path, ec)) {
        return;
    }

    auto sz = fs::file_size(log_path, ec);
    if (ec || sz < max_bytes) {
        return;
    }

    std::wstring dir = get_logs_directory();
    for (size_t i = max_backups; i > 1; --i) {
        std::wstring older = dir + L"\\audit." + std::to_wstring(i) + L".jsonl";
        std::wstring newer = dir + L"\\audit." + std::to_wstring(i - 1) + L".jsonl";
        fs::remove(older, ec);
        fs::rename(newer, older, ec);
    }

    std::wstring first_backup = dir + L"\\audit.1.jsonl";
    fs::remove(first_backup, ec);
    fs::rename(log_path, first_backup, ec);
}

static void write_audit_entry(const std::wstring& json_line) {
    std::lock_guard<std::mutex> lock(s_audit_mutex);

    AuditJournal::check_and_rotate();

    namespace fs = std::filesystem;
    const std::wstring dir = AuditJournal::get_logs_directory();
    std::error_code ec;
    fs::create_directories(dir, ec);

    const std::wstring path = AuditJournal::get_journal_file_path();
    std::wofstream out(path, std::ios::app);
    if (out.is_open()) {
        out << json_line << L"\n";
    }
}

void AuditJournal::log_before(std::wstring_view action,
                             std::wstring_view target,
                             std::wstring_view details) {
    std::wostringstream ss;
    ss << L"{\"timestamp\":\"" << get_iso_timestamp() << L"\","
       << L"\"phase\":\"before\","
       << L"\"action\":\"" << escape_json(action) << L"\","
       << L"\"target\":\"" << escape_json(target) << L"\"";
    if (!details.empty()) {
        ss << L",\"details\":\"" << escape_json(details) << L"\"";
    }
    ss << L"}";

    write_audit_entry(ss.str());
}

void AuditJournal::log_after(std::wstring_view action,
                            std::wstring_view target,
                            bool success,
                            DWORD error_code,
                            std::wstring_view details) {
    std::wostringstream ss;
    ss << L"{\"timestamp\":\"" << get_iso_timestamp() << L"\","
       << L"\"phase\":\"after\","
       << L"\"action\":\"" << escape_json(action) << L"\","
       << L"\"target\":\"" << escape_json(target) << L"\","
       << L"\"success\":" << (success ? L"true" : L"false");
    if (!success) {
        ss << L",\"error_code\":" << error_code;
    }
    if (!details.empty()) {
        ss << L",\"details\":\"" << escape_json(details) << L"\"";
    }
    ss << L"}";

    write_audit_entry(ss.str());
}

} // namespace obliterator
