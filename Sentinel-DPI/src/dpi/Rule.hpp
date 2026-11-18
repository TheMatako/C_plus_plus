// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/Rule.hpp

#pragma once

#include "../core/ProtocolType.hpp"

#include <optional>
#include <cstdint>
#include <string>
#include <string_view>

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Rule {
    uint32_t sid = 0;
    std::string msg;
    Severity severity = Severity::MEDIUM;
    std::optional<ProtocolType> protocol;
    std::optional<std::string> srcIp;
    std::optional<uint16_t> srcPort;
    std::optional<std::string> dstIp;
    std::optional<uint16_t> dstPort;
    std::optional<uint8_t> flags;
    std::optional<std::string> content;
    bool nocase = false;
};

constexpr std::string_view severityToString(Severity severity) noexcept {
    switch (severity) {
        case Severity::LOW:
            return "LOW";
        case Severity::MEDIUM:
            return "MEDIUM";
        case Severity::HIGH:
            return "HIGH";
        case Severity::CRITICAL:
            return "CRITICAL";
    }
    return "UNKNOWN";
};