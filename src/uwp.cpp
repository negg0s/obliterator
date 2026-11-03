#include "obliterator/uwp.hpp"
#include "obliterator/log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>

#include <chrono>

namespace obliterator {

std::vector<UwpPackageInfo> UwpManager::enumerate_packages() {
    std::vector<UwpPackageInfo> result;
    try {
        winrt::init_apartment();
        winrt::Windows::Management::Deployment::PackageManager pm;
        auto packages = pm.FindPackagesForUser(L"");
        for (const auto& pkg : packages) {
            try {
                if (pkg.IsFramework() || pkg.IsResourcePackage()) {
                    continue;
                }
                auto id = pkg.Id();
                std::wstring full_name = id.FullName().c_str();
                std::wstring family_name = id.FamilyName().c_str();
                std::wstring name = id.Name().c_str();
                std::wstring display_name = name;
                try {
                    auto d = pkg.DisplayName();
                    if (!d.empty()) {
                        display_name = d.c_str();
                    }
                } catch (...) {}

                std::wstring install_loc;
                try {
                    install_loc = pkg.InstalledLocation().Path().c_str();
                } catch (...) {}

                std::wstring publisher;
                try {
                    publisher = pkg.PublisherDisplayName().c_str();
                } catch (...) {}

                std::wstring install_date = L"----";
                try {
                    auto dt = pkg.InstalledDate();
                    int64_t ticks = dt.time_since_epoch().count();
                    FILETIME ft{};
                    ft.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFF);
                    ft.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
                    SYSTEMTIME st{};
                    if (FileTimeToSystemTime(&ft, &st)) {
                        wchar_t buf[32];
                        swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
                        install_date = buf;
                    }
                } catch (...) {}

                result.push_back({
                    name,
                    display_name,
                    full_name,
                    family_name,
                    install_loc,
                    publisher,
                    0,
                    install_date
                });
            } catch (...) {}
        }
    } catch (const std::exception& ex) {
        Logger::debug(std::wstring(L"Failed to query UWP packages: ") + std::wstring(ex.what(), ex.what() + strlen(ex.what())));
    } catch (...) {}
    return result;
}

Result<void> UwpManager::remove_package(const std::wstring& full_name) {
    if (full_name.empty()) {
        return Win32Error::from_code(ERROR_INVALID_PARAMETER);
    }
    try {
        winrt::init_apartment();
        winrt::Windows::Management::Deployment::PackageManager pm;
        auto op = pm.RemovePackageAsync(full_name);
        op.get();
        return Result<void>::success();
    } catch (const winrt::hresult_error& ex) {
        return Win32Error::from_code(static_cast<DWORD>(ex.code()));
    } catch (...) {
        return Win32Error::from_code(ERROR_FUNCTION_FAILED);
    }
}

std::vector<std::wstring> UwpManager::get_remnant_folders(const std::wstring& family_name) {
    std::vector<std::wstring> paths;
    if (family_name.empty()) {
        return paths;
    }

    wchar_t local_app_data[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) > 0) {
        std::wstring pkg_dir = std::wstring(local_app_data) + L"\\Packages\\" + family_name;
        paths.push_back(pkg_dir);
    }

    return paths;
}

std::vector<std::wstring> UwpManager::get_remnant_registry_subkeys(const std::wstring& family_name) {
    std::vector<std::wstring> subkeys;
    if (family_name.empty()) {
        return subkeys;
    }

    subkeys.push_back(L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\" + family_name);
    subkeys.push_back(L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\" + family_name);
    return subkeys;
}

} // namespace obliterator
