#include "obliterator/media_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

bool MediaCleaner::matches_target(const std::wstring& name, const Target& target) {
    if (name.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(name, target.name)) {
            return true;
        }
        if (name.length() >= 4 && string_contains_ignore_case(target.name, name)) {
            return true;
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3 && string_contains_ignore_case(name, folder)) {
                return true;
            }
        }
    }

    return false;
}

bool MediaCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

bool MediaCleaner::inspect_inproc_server(HKEY root, const std::wstring& clsid_str, const Target& target) {
    if (clsid_str.empty()) {
        return false;
    }

    const std::wstring clsid_key = L"Software\\Classes\\CLSID\\" + clsid_str + L"\\InprocServer32";
    UniqueHKey hInproc;
    if (RegOpenKeyExW(root, clsid_key.c_str(), 0, KEY_READ, hInproc.put()) != ERROR_SUCCESS) {
        return false;
    }

    wchar_t path_buf[MAX_PATH] = { 0 };
    DWORD path_len = sizeof(path_buf);
    DWORD type = 0;
    if (RegQueryValueExW(hInproc.get(), nullptr, nullptr, &type,
                         reinterpret_cast<BYTE*>(path_buf), &path_len) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        return path_references_target(path_buf, target);
    }

    return false;
}

MediaCleanReport MediaCleaner::clean_media_artifacts(const Target& target, bool dry_run) {
    MediaCleanReport report;
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    // 1. DirectShow Filters Category Instances
    const wchar_t* const kDirectShowInstance =
        L"Software\\Classes\\CLSID\\{083863F1-70DE-11D0-BD40-00A0C911CE86}\\Instance";

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hInstance;
        if (RegOpenKeyExW(root, kDirectShowInstance, 0, access, hInstance.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hInstance.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        struct FilterMatch {
            std::wstring instance_name;
            std::wstring clsid;
        };
        std::vector<FilterMatch> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hInstance.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring inst_name(name_buf.data(), len);
            UniqueHKey hFilter;
            if (RegOpenKeyExW(hInstance.get(), inst_name.c_str(), 0, KEY_READ, hFilter.put()) != ERROR_SUCCESS) {
                continue;
            }

            bool matched = false;
            std::wstring target_clsid;

            // Check FriendlyName
            wchar_t fname_buf[MAX_PATH] = { 0 };
            DWORD fname_len = sizeof(fname_buf);
            DWORD type = 0;
            if (RegQueryValueExW(hFilter.get(), L"FriendlyName", nullptr, &type,
                                 reinterpret_cast<BYTE*>(fname_buf), &fname_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                if (matches_target(fname_buf, target)) {
                    matched = true;
                }
            }

            // Check CLSID value
            wchar_t clsid_buf[MAX_PATH] = { 0 };
            DWORD clsid_len = sizeof(clsid_buf);
            if (RegQueryValueExW(hFilter.get(), L"CLSID", nullptr, &type,
                                 reinterpret_cast<BYTE*>(clsid_buf), &clsid_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                target_clsid = clsid_buf;
                if (!matched && inspect_inproc_server(root, target_clsid, target)) {
                    matched = true;
                }
            }

            // Also check if instance name itself is a CLSID
            if (!matched && inst_name.length() >= 36 && inst_name.front() == L'{') {
                if (inspect_inproc_server(root, inst_name, target)) {
                    matched = true;
                    if (target_clsid.empty()) {
                        target_clsid = inst_name;
                    }
                }
            }

            if (matched) {
                to_delete.push_back({inst_name, target_clsid});
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hInstance.get(), item.instance_name.c_str());
                if (!item.clsid.empty()) {
                    const std::wstring full_clsid_key = L"Software\\Classes\\CLSID\\" + item.clsid;
                    RegDeleteTreeW(root, full_clsid_key.c_str());
                }
            }
            ++report.directshow_filters_removed;
            report.details.push_back(L"DirectShow Filter: " + item.instance_name);
        }
    }

    // 2. Media Foundation Transforms
    const wchar_t* const kMfTransforms = L"Software\\Classes\\MediaFoundation\\Transforms";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hTransforms;
        if (RegOpenKeyExW(root, kMfTransforms, 0, access, hTransforms.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD cat_count = 0;
        DWORD max_cat_len = 0;
        if (RegQueryInfoKeyW(hTransforms.get(), nullptr, nullptr, nullptr, &cat_count,
                             &max_cat_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> cat_buf(max_cat_len + 2, L'\0');

        for (DWORD i = 0; i < cat_count; ++i) {
            DWORD cat_len = static_cast<DWORD>(cat_buf.size());
            if (RegEnumKeyExW(hTransforms.get(), i, cat_buf.data(), &cat_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring cat_name(cat_buf.data(), cat_len);
            UniqueHKey hCat;
            if (RegOpenKeyExW(hTransforms.get(), cat_name.c_str(), 0, access, hCat.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_sub_len = 0;
            if (RegQueryInfoKeyW(hCat.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_sub_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> sub_buf(max_sub_len + 2, L'\0');
            std::vector<std::wstring> to_delete;

            for (DWORD j = 0; j < subkey_count; ++j) {
                DWORD sub_len = static_cast<DWORD>(sub_buf.size());
                if (RegEnumKeyExW(hCat.get(), j, sub_buf.data(), &sub_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring clsid_sub(sub_buf.data(), sub_len);
                if (inspect_inproc_server(root, clsid_sub, target) || matches_target(clsid_sub, target)) {
                    to_delete.push_back(clsid_sub);
                }
            }

            for (const auto& clsid_del : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hCat.get(), clsid_del.c_str());
                    const std::wstring full_clsid_key = L"Software\\Classes\\CLSID\\" + clsid_del;
                    RegDeleteTreeW(root, full_clsid_key.c_str());
                }
                ++report.mf_transforms_removed;
                report.details.push_back(L"Media Foundation Transform: " + clsid_del);
            }
        }
    }

    // 3. Media Foundation ByteStreamHandlers
    const wchar_t* const kByteStream = L"Software\\Microsoft\\Windows Media Foundation\\ByteStreamHandlers";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hByteStream;
        if (RegOpenKeyExW(root, kByteStream, 0, access, hByteStream.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD ext_count = 0;
        DWORD max_ext_len = 0;
        if (RegQueryInfoKeyW(hByteStream.get(), nullptr, nullptr, nullptr, &ext_count,
                             &max_ext_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> ext_buf(max_ext_len + 2, L'\0');

        for (DWORD i = 0; i < ext_count; ++i) {
            DWORD ext_len = static_cast<DWORD>(ext_buf.size());
            if (RegEnumKeyExW(hByteStream.get(), i, ext_buf.data(), &ext_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring ext_name(ext_buf.data(), ext_len);
            UniqueHKey hExt;
            if (RegOpenKeyExW(hByteStream.get(), ext_name.c_str(), 0, access, hExt.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD val_count = 0;
            DWORD max_val_len = 0;
            if (RegQueryInfoKeyW(hExt.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> val_buf(max_val_len + 2, L'\0');
            std::vector<std::wstring> vals_to_delete;

            for (DWORD j = 0; j < val_count; ++j) {
                DWORD vlen = static_cast<DWORD>(val_buf.size());
                if (RegEnumValueW(hExt.get(), j, val_buf.data(), &vlen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring val_name(val_buf.data(), vlen);
                if (inspect_inproc_server(root, val_name, target)) {
                    vals_to_delete.push_back(val_name);
                }
            }

            for (const auto& v : vals_to_delete) {
                if (!dry_run) {
                    RegDeleteValueW(hExt.get(), v.c_str());
                }
                ++report.bytestream_handlers_removed;
                report.details.push_back(L"ByteStreamHandler: " + ext_name + L" -> " + v);
            }
        }
    }

    return report;
}

} // namespace obliterator
