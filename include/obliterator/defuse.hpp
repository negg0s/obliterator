#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/plan.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct DefuseReport {
    size_t service_failure_actions_cleared{0};
    size_t services_disabled{0};
    size_t tasks_disabled{0};
    size_t autorun_entries_defused{0};
    size_t wmi_subscriptions_removed{0};
    std::vector<std::wstring> warnings;
};

class RecoveryDefuser {
public:
    static DefuseReport defuse_all(const Target& target,
                                  const std::vector<PlanService>& services,
                                  const std::vector<PlanTask>& tasks);

    static DefuseReport defuse_all(const Target& target,
                                  const std::vector<ServiceInfo>& services,
                                  const std::vector<ScheduledTaskInfo>& tasks);

    static bool defuse_service(SC_HANDLE scm, const std::wstring& service_name);
    static bool disable_task(const std::wstring& task_name);
    static size_t defuse_autorun_entries(const Target& target);
    static size_t defuse_wmi_subscriptions(const Target& target);
};

} // namespace obliterator
