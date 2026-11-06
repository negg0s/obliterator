#include "obliterator/bits_cleaner.hpp"

#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <bits.h>
#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

static const GUID kClsidBackgroundCopyManager =
    { 0x4996456c, 0x0e88, 0x4276, { 0x83, 0x4e, 0x03, 0x0b, 0xb7, 0x37, 0x87, 0x78 } };
static const GUID kIidIBackgroundCopyManager =
    { 0x5ce34c0d, 0x0dc9, 0x4c1f, { 0x89, 0x7c, 0xda, 0xa1, 0xb7, 0x8c, 0xee, 0x77 } };

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

bool BitsCleaner::path_references_target(const std::wstring& path, const Target& target) {
    if (path.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        if (PathHelper::contains_path_reference(path, target.root_path)) {
            return true;
        }
        const std::wstring norm_path = SafetyValidator::normalize_path(path);
        if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
            return true;
        }
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(path, target.name)) {
            return true;
        }
    }

    return false;
}

BitsCleanReport BitsCleaner::clean_bits_jobs(const Target& target, bool dry_run) {
    BitsCleanReport report;

    HRESULT hr_co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool need_uninit = SUCCEEDED(hr_co);

    IBackgroundCopyManager* pManager = nullptr;
    HRESULT hr = CoCreateInstance(kClsidBackgroundCopyManager, nullptr, CLSCTX_LOCAL_SERVER,
                                  kIidIBackgroundCopyManager, reinterpret_cast<void**>(&pManager));
    if (FAILED(hr) || !pManager) {
        if (need_uninit) {
            CoUninitialize();
        }
        return report;
    }

    IEnumBackgroundCopyJobs* pEnumJobs = nullptr;
    // Attempt to enumerate all users' jobs first; fallback to current user jobs
    hr = pManager->EnumJobs(1 /* BG_JOB_ENUM_ALL_USERS */, &pEnumJobs);
    if (FAILED(hr) || !pEnumJobs) {
        hr = pManager->EnumJobs(0, &pEnumJobs);
    }

    if (SUCCEEDED(hr) && pEnumJobs) {
        IBackgroundCopyJob* pJob = nullptr;
        ULONG fetched = 0;

        while (pEnumJobs->Next(1, &pJob, &fetched) == S_OK && fetched == 1) {
            LPWSTR pJobName = nullptr;
            std::wstring job_name;
            if (SUCCEEDED(pJob->GetDisplayName(&pJobName)) && pJobName) {
                job_name = pJobName;
                CoTaskMemFree(pJobName);
            }

            bool matched = false;
            if (path_references_target(job_name, target)) {
                matched = true;
            }

            // Inspect files associated with the job
            if (!matched) {
                IEnumBackgroundCopyFiles* pEnumFiles = nullptr;
                if (SUCCEEDED(pJob->EnumFiles(&pEnumFiles)) && pEnumFiles) {
                    IBackgroundCopyFile* pFile = nullptr;
                    ULONG files_fetched = 0;

                    while (!matched && pEnumFiles->Next(1, &pFile, &files_fetched) == S_OK && files_fetched == 1) {
                        LPWSTR pLocalName = nullptr;
                        if (SUCCEEDED(pFile->GetLocalName(&pLocalName)) && pLocalName) {
                            std::wstring local_path = pLocalName;
                            CoTaskMemFree(pLocalName);
                            if (path_references_target(local_path, target)) {
                                matched = true;
                            }
                        }

                        LPWSTR pRemoteName = nullptr;
                        if (!matched && SUCCEEDED(pFile->GetRemoteName(&pRemoteName)) && pRemoteName) {
                            std::wstring remote_url = pRemoteName;
                            CoTaskMemFree(pRemoteName);
                            if (path_references_target(remote_url, target)) {
                                matched = true;
                            }
                        }

                        pFile->Release();
                    }
                    pEnumFiles->Release();
                }
            }

            if (matched) {
                if (!dry_run) {
                    pJob->Cancel();
                }
                ++report.jobs_cancelled;
                report.details.push_back(L"BITS Job: " + (job_name.empty() ? L"(unnamed)" : job_name));
            }

            pJob->Release();
        }

        pEnumJobs->Release();
    }

    pManager->Release();
    if (need_uninit) {
        CoUninitialize();
    }

    return report;
}

} // namespace obliterator
