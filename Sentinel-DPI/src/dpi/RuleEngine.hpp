// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/RuleEngine.hpp

#pragma once

#include "Rule.hpp"
#include "Alert.hpp"
#include "../core/Packet.hpp"

#include <vector>
#include <cstddef>

class RuleEngine {
    private:
        std::vector<Rule> rules_;
    public:
        explicit RuleEngine(std::vector<Rule> rules);
        std::vector<Alert> inspect(const Packet& packet) const;
        std::size_t ruleCount() const noexcept;
        const std::vector<Rule>& getRules() const noexcept;
};