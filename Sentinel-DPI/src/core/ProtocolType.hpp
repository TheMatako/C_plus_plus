// ========================== //
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/core/ProtocolType.hpp

#pragma once

#include <cstdint>
#include <ostream>
#include <string_view>

enum class ProtocolType: uint8_t {
    Ethernet,
    IPv4,
    TCP,
    UDP,
    ICMP,
    Payload
};

constexpr std::string_view protocolToString(ProtocolType protocolType) noexcept {
    switch (protocolType) {
        case ProtocolType::Ethernet:  return "Ethernet";
        case ProtocolType::IPv4:      return "IPv4";
        case ProtocolType::TCP:       return "TCP";
        case ProtocolType::UDP:       return "UDP";
        case ProtocolType::ICMP:      return "ICMP";
        case ProtocolType::Payload:   return "Payload"; 
    }
    return "UNKNOWN";
}   

inline std::ostream& operator<<(std::ostream& os, ProtocolType protocolType) {
    return os << protocolToString(protocolType);
}