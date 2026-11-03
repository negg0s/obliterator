#pragma once

#include "obliterator/cli.hpp"
#include "obliterator/confidence_engine.hpp"
#include "obliterator/report.hpp"
#include "obliterator/target.hpp"

#include <functional>
#include <string>
#include <vector>

namespace obliterator {

using PhaseCallback = std::function<void(size_t phase, const std::wstring& name)>;
using LogCallback = std::function<void(const std::wstring& line)>;
using CancelCheck = std::function<bool()>;

FinalReport execute_obliteration(
    const Target& target,
    const CommandLineOptions& options,
    const std::vector<ScoredArtifact>& excluded_artifacts,
    PhaseCallback on_phase = nullptr,
    LogCallback on_log = nullptr,
    CancelCheck is_cancelling = nullptr
);

} // namespace obliterator
