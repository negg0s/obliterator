#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct ResumeState {
    std::wstring target_name;
    std::wstring target_root;
    std::vector<std::wstring> pending_files;
    std::vector<std::wstring> pending_directories;
    std::vector<std::wstring> pending_services;
    std::vector<std::wstring> pending_drivers;
    bool aggressive{false};
    std::wstring created_at;
};

class ResumeManager {
public:
    static std::wstring get_resume_directory();
    static std::wstring get_resume_file_path();

    static bool save_resume_state(const ResumeState& state);
    static bool has_resume_state();
    static bool load_resume_state(ResumeState& out_state);

    // Executes resume pass without UI/interaction, writes report and cleans state on completion
    static int execute_resume();

    // Removes the RunOnce entry and deletes resume.json
    static void cleanup_resume_state();

    static bool register_run_once();
    static bool unregister_run_once();
};

} // namespace obliterator
