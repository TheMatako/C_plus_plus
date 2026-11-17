// ========================== //
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/core/ProtocolType.hpp

#pragma once

#include <cstdint>

enum class ProtocolType: uint8_t {
    Ethernet,
    IPv4,
    TCP,
    UDP,
    ICMP,
    Payload
};