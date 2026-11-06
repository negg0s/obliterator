#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/cli.hpp"

#include <string>

namespace obliterator {

class RpcServer {
public:
    // Runs the JSON-RPC / NDJSON headless event loop on stdin/stdout until exit command or EOF
    static int run(const CommandLineOptions& base_options);

    // Processes a single JSON-RPC line request and generates response string
    static std::wstring handle_request_line(const std::wstring& line, const CommandLineOptions& base_options, bool& should_exit);
};

} // namespace obliterator
