#pragma once

#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct PlanRegistryKey {
    HKEY root_key;
    std::wstring subkey_path;
    REGSAM sam_view;
    std::wstring description;
};

struct Plan {
    Target target;
    std::vector<std::wstring> directories_to_remove;
    std::vector<PlanRegistryKey> registry_keys_to_remove;

    explicit Plan(Target t);

    void print() const;
    [[nodiscard]] bool is_empty() const noexcept;
};

} // namespace obliterator
