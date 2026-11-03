#include "obliterator/cli.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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

    // Split input into argument tokens separated by space or newline
    std::vector<std::wstring> args;
    size_t start = 0;
    while (start < input.size()) {
        while (start < input.size() && (input[start] == L' ' || input[start] == L'\n' || input[start] == L'\t')) {
            start++;
        }
        if (start >= input.size()) {
            break;
        }
        size_t end = input.find_first_of(L" \n\t", start);
        if (end == std::wstring::npos) {
            end = input.size();
        }
        args.emplace_back(input.substr(start, end - start));
        start = end;
    }

    (void)CommandLineParser::parse(args);

    return 0;
}
