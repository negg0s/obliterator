#include "obliterator/usn_journal.hpp"

#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/volume.hpp"

#include <cwctype>
#include <vector>

namespace obliterator {

static bool string_equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) return false;
    const std::wstring t = PathHelper::to_lower_unicode(text);
    const std::wstring n = PathHelper::to_lower_unicode(needle);
    return t.find(n) != std::wstring::npos;
}

static std::wstring format_volume_device_path(const std::wstring& drive_root) {
    std::wstring d = VolumeManager::get_path_drive(drive_root);
    if (d.empty()) {
        d = L"C:";
    }
    return L"\\\\.\\" + d;
}

bool UsnJournalScanner::is_usn_supported(const std::wstring& drive_root) {
    std::wstring dev = format_volume_device_path(drive_root);
    UniqueHandle hVol(CreateFileW(
        dev.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    ));
    if (!hVol) {
        return false;
    }

    USN_JOURNAL_DATA_V0 ujd{};
    DWORD bytes = 0;
    return DeviceIoControl(hVol.get(), FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                           &ujd, sizeof(ujd), &bytes, nullptr) != 0;
}

Result<std::vector<UsnMatchedFolder>> UsnJournalScanner::scan_volume_for_directories(
    const std::wstring& drive_root,
    std::wstring_view target_name,
    std::wstring_view publisher_name
) {
    std::vector<UsnMatchedFolder> matched_folders;
    if (target_name.empty() && publisher_name.empty()) {
        return matched_folders;
    }

    std::wstring dev = format_volume_device_path(drive_root);
    UniqueHandle hVol(CreateFileW(
        dev.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    ));
    if (!hVol) {
        return Win32Error::from_code(GetLastError());
    }

    USN_JOURNAL_DATA_V0 ujd{};
    DWORD bytes_ret = 0;
    if (!DeviceIoControl(hVol.get(), FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                         &ujd, sizeof(ujd), &bytes_ret, nullptr)) {
        return Win32Error::from_code(GetLastError());
    }

    MFT_ENUM_DATA_V0 med{};
    med.StartFileReferenceNumber = 0;
    med.LowUsn = 0;
    med.HighUsn = ujd.NextUsn;

    constexpr size_t kBufferSize = 64 * 1024;
    std::vector<BYTE> buffer(kBufferSize);

    while (true) {
        if (!DeviceIoControl(hVol.get(), FSCTL_ENUM_USN_DATA, &med, sizeof(med),
                             buffer.data(), static_cast<DWORD>(buffer.size()),
                             &bytes_ret, nullptr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF || err == ERROR_SUCCESS) {
                break;
            }
            return Win32Error::from_code(err);
        }

        if (bytes_ret <= sizeof(USN)) {
            break;
        }

        // First 8 bytes returned in buffer is the NextUSN to continue enumeration
        med.StartFileReferenceNumber = *reinterpret_cast<DWORDLONG*>(buffer.data());

        BYTE* cur = buffer.data() + sizeof(USN);
        const BYTE* end = buffer.data() + bytes_ret;

        while (cur < end) {
            auto* record = reinterpret_cast<USN_RECORD_V2*>(cur);
            if (record->RecordLength == 0) {
                break;
            }

            if ((record->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && record->FileNameLength > 0) {
                const auto* name_ptr = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const BYTE*>(record) + record->FileNameOffset
                );
                const size_t name_chars = record->FileNameLength / sizeof(wchar_t);
                std::wstring_view name_view(name_ptr, name_chars);

                bool is_match = false;
                if (!target_name.empty() && string_equals_ignore_case(name_view, target_name)) {
                    is_match = true;
                } else if (!publisher_name.empty() && string_equals_ignore_case(name_view, publisher_name)) {
                    is_match = true;
                } else if (!target_name.empty() && target_name.size() >= 4 && string_contains_ignore_case(name_view, target_name)) {
                    is_match = true;
                }

                if (is_match) {
                    FILE_ID_DESCRIPTOR desc{};
                    desc.dwSize = sizeof(desc);
                    desc.Type = FileIdType;
                    desc.FileId.QuadPart = static_cast<LONGLONG>(record->FileReferenceNumber);

                    UniqueHandle hFolder(OpenFileById(
                        hVol.get(),
                        &desc,
                        FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr,
                        FILE_FLAG_BACKUP_SEMANTICS
                    ));

                    if (hFolder) {
                        wchar_t path_buf[MAX_PATH * 2]{};
                        DWORD path_len = GetFinalPathNameByHandleW(
                            hFolder.get(),
                            path_buf,
                            static_cast<DWORD>(std::size(path_buf)),
                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
                        );
                        if (path_len > 0 && path_len < std::size(path_buf)) {
                            std::wstring full_path(path_buf, path_len);
                            if (full_path.starts_with(L"\\\\?\\")) {
                                full_path.erase(0, 4);
                            }

                            if (SafetyValidator::validate_path(full_path)) {
                                UsnMatchedFolder matched;
                                matched.folder_name = std::wstring(name_view);
                                matched.file_reference_number = record->FileReferenceNumber;
                                matched.parent_reference_number = record->ParentFileReferenceNumber;
                                matched.full_path = std::move(full_path);
                                matched_folders.push_back(std::move(matched));
                            }
                        }
                    }
                }
            }

            cur += record->RecordLength;
        }
    }

    return matched_folders;
}

} // namespace obliterator
