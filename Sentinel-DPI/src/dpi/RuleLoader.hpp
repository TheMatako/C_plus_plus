// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/RuleLoader.hpp

#pragma once

#include "Rule.hpp"

#include <string>
#include <vector>

namespace RuleLoader {
    std::vector<Rule> loadRules(const std::string& filePath);
};