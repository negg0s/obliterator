#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>

namespace obliterator {

class CryptoHelper {
public:
    // Computes SHA-256 hash using BCrypt CNG API and returns a 64-character lowercase hex string
    static std::wstring compute_sha256_file(const std::wstring& file_path);
    static std::wstring compute_sha256_bytes(const void* data, size_t size);
};

} // namespace obliterator
