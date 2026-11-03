#include "obliterator/service.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

using namespace obliterator;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Convert raw input to wide string
    std::wstring input;
    input.reserve(size / sizeof(wchar_t) + 1);
    const size_t num_chars = size / sizeof(wchar_t);
    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    input.assign(wdata, num_chars);

    // Call service image path normalization
    (void)ServiceManager::normalize_service_image_path(input);

    return 0;
}
