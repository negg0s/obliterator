#include "obliterator/path.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

using namespace obliterator;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < sizeof(wchar_t)) {
        return 0;
    }

    const size_t num_wchars = size / sizeof(wchar_t);
    const auto* wchars = reinterpret_cast<const wchar_t*>(data);
    std::wstring input(wchars, num_wchars);

    (void)PathHelper::normalize(input);
    (void)PathHelper::canonicalize(input);
    (void)PathHelper::split_components(input);
    (void)PathHelper::to_lower_unicode(input);

    size_t split = input.find(L'|');
    if (split != std::wstring::npos) {
        std::wstring part1 = input.substr(0, split);
        std::wstring part2 = input.substr(split + 1);
        (void)PathHelper::is_same_or_subpath(part1, part2);
        (void)PathHelper::contains_path_reference(part1, part2);
    } else {
        (void)PathHelper::is_same_or_subpath(L"C:\\Program Files\\App", input);
        (void)PathHelper::contains_path_reference(input, L"C:\\Program Files\\App");
    }

    return 0;
}
