cmake_minimum_required(VERSION 3.20)

project(obliterator
    VERSION 0.3.0
    LANGUAGES CXX RC
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT for all configurations
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(UNICODE _UNICODE)

if(MSVC)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}_${CMAKE_SYSTEM_PROCESSOR}_${CMAKE_VS_PLATFORM_NAME}" _arch_lower)
    if(_arch_lower MATCHES "arm64")
        set(IS_ARM64_TARGET TRUE)
    else()
        set(IS_ARM64_TARGET FALSE)
    endif()

    add_compile_options(
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
        /GS
        /guard:cf
        $<$<CONFIG:Release>:/Qspectre>
    )

    add_link_options(
        /GUARD:CF
        /DYNAMICBASE
        /HIGHENTROPYVA
        /Brepro
    )

    if(NOT IS_ARM64_TARGET)
        add_link_options(/CETCOMPAT)
    endif()
endif()

add_library(obliterator_core STATIC
    include/obliterator/app_type.hpp
    include/obliterator/cli.hpp
    include/obliterator/error.hpp
    include/obliterator/handles.hpp
    include/obliterator/log.hpp
    include/obliterator/path.hpp
    include/obliterator/plan.hpp
    include/obliterator/privileges.hpp
    include/obliterator/process.hpp
    include/obliterator/result.hpp
    include/obliterator/confidence_config.hpp
    include/obliterator/confidence_engine.hpp
    include/obliterator/registry_cleaner.hpp
    include/obliterator/leftovers.hpp
    include/obliterator/report.hpp
    include/obliterator/safety.hpp
    include/obliterator/service.hpp
    include/obliterator/target.hpp
    include/obliterator/ui.hpp
    include/obliterator/uninstaller.hpp
    include/obliterator/unlocker.hpp
    include/obliterator/uwp.hpp
    include/obliterator/portable.hpp
    include/obliterator/profile.hpp
    include/obliterator/defuse.hpp
    include/obliterator/pending_rename.hpp
    include/obliterator/resume.hpp
    include/obliterator/safe_mode.hpp
    include/obliterator/restore_point.hpp
    include/obliterator/crypto.hpp
    include/obliterator/diagnose.hpp
    include/obliterator/audit.hpp
    include/obliterator/quarantine.hpp
    include/obliterator/wiper.hpp
    include/obliterator/tui_model.hpp
    include/obliterator/tui.hpp
    include/obliterator/executor.hpp
    include/obliterator/volume.hpp
    include/obliterator/rpc.hpp
    include/obliterator/batch.hpp
    include/obliterator/shell_cleaner.hpp
    include/obliterator/usn_journal.hpp
    include/obliterator/msi_cleaner.hpp
    include/obliterator/driver_cleaner.hpp
    include/obliterator/ads.hpp
    include/obliterator/cert_cleaner.hpp
    include/obliterator/wfp_cleaner.hpp
    include/obliterator/association_cleaner.hpp
    include/obliterator/event_log_cleaner.hpp
    include/obliterator/wer_cleaner.hpp
    include/obliterator/app_compat_cleaner.hpp
    include/obliterator/notification_cleaner.hpp
    include/obliterator/bits_cleaner.hpp
    include/obliterator/ifeo_cleaner.hpp
    include/obliterator/power_cleaner.hpp
    include/obliterator/recent_apps_cleaner.hpp
    include/obliterator/gpu_cleaner.hpp
    include/obliterator/user_assist_cleaner.hpp
    include/obliterator/audio_cleaner.hpp
    include/obliterator/defender_cleaner.hpp
    include/obliterator/comdlg_cleaner.hpp
    include/obliterator/console_cleaner.hpp
    src/cli.cpp
    src/confidence_engine.cpp
    src/defuse.cpp
    src/error.cpp
    src/leftovers.cpp
    src/log.cpp
    src/path.cpp
    src/pending_rename.cpp
    src/plan.cpp
    src/portable.cpp
    src/privileges.cpp
    src/process.cpp
    src/profile.cpp
    src/registry_cleaner.cpp
    src/report.cpp
    src/resume.cpp
    src/safe_mode.cpp
    src/restore_point.cpp
    src/crypto.cpp
    src/diagnose.cpp
    src/audit.cpp
    src/quarantine.cpp
    src/safety.cpp
    src/service.cpp
    src/target.cpp
    src/ui.cpp
    src/uninstaller.cpp
    src/unlocker.cpp
    src/uwp.cpp
    src/wiper.cpp
    src/tui_model.cpp
    src/tui.cpp
    src/executor.cpp
    src/volume.cpp
    src/rpc.cpp
    src/batch.cpp
    src/shell_cleaner.cpp
    src/usn_journal.cpp
    src/msi_cleaner.cpp
    src/driver_cleaner.cpp
    src/ads.cpp
    src/cert_cleaner.cpp
    src/wfp_cleaner.cpp
    src/association_cleaner.cpp
    src/event_log_cleaner.cpp
    src/wer_cleaner.cpp
    src/app_compat_cleaner.cpp
    src/notification_cleaner.cpp
    src/bits_cleaner.cpp
    src/ifeo_cleaner.cpp
    src/power_cleaner.cpp
    src/recent_apps_cleaner.cpp
    src/gpu_cleaner.cpp
    src/user_assist_cleaner.cpp
    src/audio_cleaner.cpp
    src/defender_cleaner.cpp
    src/comdlg_cleaner.cpp
    src/console_cleaner.cpp
)

target_include_directories(obliterator_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(obliterator_core PUBLIC
    advapi32
    bcrypt
    crypt32
    ntdll
    rstrtmgr
    taskschd
    ole32
    oleaut32
    shell32
    wbemuuid
    windowsapp
)

if(MSVC)
    target_compile_options(obliterator_core PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
    )
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
    @ONLY
)

add_executable(obliterator
    src/main.cpp
    src/app.manifest
    "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
)

target_link_libraries(obliterator PRIVATE
    obliterator_core
)

if(MSVC)
    set_target_properties(obliterator PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\""
    )
endif()

enable_testing()

add_executable(test_blocker
    tests/blocker.cpp
)

if(MSVC)
    target_compile_options(test_blocker PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
    )
endif()

add_executable(obliterator_tests
    tests/test_main.cpp
)

add_dependencies(obliterator_tests test_blocker)

target_link_libraries(obliterator_tests PRIVATE
    obliterator_core
)

if(MSVC)
    target_compile_options(obliterator_tests PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
    )
endif()

add_test(NAME unit_tests COMMAND obliterator_tests)

add_executable(bench
    tests/bench.cpp
)

target_link_libraries(bench PRIVATE
    obliterator_core
)

if(MSVC)
    target_compile_options(bench PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
    )
endif()

option(ENABLE_FUZZING "Build libFuzzer targets" OFF)
if(ENABLE_FUZZING AND MSVC)
    set_target_properties(obliterator test_blocker obliterator_tests bench PROPERTIES EXCLUDE_FROM_ALL TRUE)
    target_compile_options(obliterator_core PRIVATE /fsanitize=address /fsanitize=fuzzer)

    add_executable(fuzz_service_image_path tests/fuzz/fuzz_service_image_path.cpp)
    target_link_libraries(fuzz_service_image_path PRIVATE obliterator_core)
    target_compile_options(fuzz_service_image_path PRIVATE /fsanitize=address /fsanitize=fuzzer /EHsc /W4 /WX /utf-8)

    add_executable(fuzz_uninstall_string tests/fuzz/fuzz_uninstall_string.cpp)
    target_link_libraries(fuzz_uninstall_string PRIVATE obliterator_core)
    target_compile_options(fuzz_uninstall_string PRIVATE /fsanitize=address /fsanitize=fuzzer /EHsc /W4 /WX /utf-8)

    add_executable(fuzz_registry_paths tests/fuzz/fuzz_registry_paths.cpp)
    target_link_libraries(fuzz_registry_paths PRIVATE obliterator_core)
    target_compile_options(fuzz_registry_paths PRIVATE /fsanitize=address /fsanitize=fuzzer /EHsc /W4 /WX /utf-8)

    add_executable(fuzz_cli_args tests/fuzz/fuzz_cli_args.cpp)
    target_link_libraries(fuzz_cli_args PRIVATE obliterator_core)
    target_compile_options(fuzz_cli_args PRIVATE /fsanitize=address /fsanitize=fuzzer /EHsc /W4 /WX /utf-8)
endif()
