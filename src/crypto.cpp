#include "obliterator/crypto.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/wiper.hpp"

#include <bcrypt.h>

#include <iomanip>
#include <sstream>
#include <vector>

namespace obliterator {

static std::wstring bytes_to_hex(const BYTE* data, size_t len) {
    std::wostringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

std::wstring CryptoHelper::compute_sha256_bytes(const void* data, size_t size) {
    if (data == nullptr && size > 0) {
        return {};
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0 || hAlg == nullptr) {
        return {};
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status < 0 || hHash == nullptr) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    if (size > 0) {
        BCryptHashData(hHash, static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(size), 0);
    }

    BYTE hash_bytes[32]{};
    BCryptFinishHash(hHash, hash_bytes, sizeof(hash_bytes), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return bytes_to_hex(hash_bytes, sizeof(hash_bytes));
}

std::wstring CryptoHelper::compute_sha256_file(const std::wstring& file_path) {
    if (file_path.empty()) {
        return {};
    }

    const std::wstring ext_path = FileWiper::ensure_extended_path(file_path);
    UniqueHandle hFile(CreateFileW(
        ext_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    ));

    if (!hFile) {
        return {};
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0 || hAlg == nullptr) {
        return {};
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status < 0 || hHash == nullptr) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    constexpr DWORD kChunkSize = 64 * 1024;
    std::vector<BYTE> buffer(kChunkSize);
    DWORD bytes_read = 0;

    while (ReadFile(hFile.get(), buffer.data(), kChunkSize, &bytes_read, nullptr) && bytes_read > 0) {
        BCryptHashData(hHash, buffer.data(), bytes_read, 0);
    }

    BYTE hash_bytes[32]{};
    BCryptFinishHash(hHash, hash_bytes, sizeof(hash_bytes), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return bytes_to_hex(hash_bytes, sizeof(hash_bytes));
}

} // namespace obliterator
