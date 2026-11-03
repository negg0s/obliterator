cmake_minimum_required(VERSION 3.20)

project(obliterator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(UNICODE _UNICODE)

add_library(obliterator_core STATIC
    include/obliterator/error.hpp
    include/obliterator/handles.hpp
    include/obliterator/log.hpp
    include/obliterator/plan.hpp
    include/obliterator/privileges.hpp
    include/obliterator/process.hpp
    include/obliterator/result.hpp
    include/obliterator/registry_cleaner.hpp
    include/obliterator/leftovers.hpp
    include/obliterator/safety.hpp
    include/obliterator/service.hpp
    include/obliterator/target.hpp
    include/obliterator/unlocker.hpp
    include/obliterator/wiper.hpp
    src/error.cpp
    src/leftovers.cpp
    src/log.cpp
    src/plan.cpp
    src/privileges.cpp
    src/process.cpp
    src/registry_cleaner.cpp
    src/safety.cpp
    src/service.cpp
    src/target.cpp
    src/unlocker.cpp
    src/wiper.cpp
)

target_include_directories(obliterator_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(obliterator_core PUBLIC
    advapi32
    ntdll
    rstrtmgr
    taskschd
    ole32
    oleaut32
    shell32
)

if(MSVC)
    target_compile_options(obliterator_core PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
    )
endif()

add_executable(obliterator
    src/main.cpp
    src/app.manifest
)

target_link_libraries(obliterator PRIVATE
    obliterator_core
)

if(MSVC)
    target_compile_options(obliterator PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
    )

    set_target_properties(obliterator PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

enable_testing()

add_executable(obliterator_tests
    tests/test_main.cpp
)

target_link_libraries(obliterator_tests PRIVATE
    obliterator_core
)

if(MSVC)
    target_compile_options(obliterator_tests PRIVATE
        /W4
        /WX
        /permissive-
        /utf-8
    )
endif()

add_test(NAME unit_tests COMMAND obliterator_tests)
