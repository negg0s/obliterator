#pragma once

#include "obliterator/result.hpp"

#include <string_view>

namespace obliterator {

Result<void> enable_privilege(const wchar_t* privilege_name);
Result<void> enable_required_privileges();

} // namespace obliterator
