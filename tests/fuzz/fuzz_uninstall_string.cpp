#include "obliterator/target.hpp"

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

    // Split input into 3 components by delimiter '\n' or '\0'
    std::wstring loc;
    std::wstring icon;
    std::wstring uninst;

    size_t first = input.find(L'\n');
    if (first == std::wstring::npos) {
        uninst = input;
    } else {
        loc = input.substr(0, first);
        size_t second = input.find(L'\n', first + 1);
        if (second == std::wstring::npos) {
            uninst = input.substr(first + 1);
        } else {
            icon = input.substr(first + 1, second - first - 1);
            uninst = input.substr(second + 1);
        }
    }

    (void)TargetResolver::deduce_install_folder(loc, icon, uninst);

    return 0;
}
