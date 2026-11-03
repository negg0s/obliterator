#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

class PathHelper {
public:
    static std::wstring normalize(std::wstring_view path);
    static std::wstring canonicalize(std::wstring_view path);
    static std::wstring to_lower_unicode(std::wstring_view input);
    static std::vector<std::wstring> split_components(std::wstring_view path);
    static bool is_same_or_subpath(std::wstring_view parent_root, std::wstring_view candidate);
    static bool contains_path_reference(std::wstring_view text, std::wstring_view parent_root);
};

} // namespace obliterator
