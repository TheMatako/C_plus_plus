// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PacketParser.hpp

#pragma once

#include "../core/Packet.hpp"
#include "../core/ProtocolType.hpp"

#include <cstdint>
#include <span>

/// @brief Static parser that decodes a raw network frame into a stack of protocol layers
/// Currently protocols supported are: Ethernet, IPv4, TCP, and UDP (see src/core/ProtocolType.hpp for all supported protocols at this moment). 
namespace PacketParser {
    /// @brief Parses a raw byte buffer starting from an initial protocol and returns the structured Packet.
    static Packet parse(
        std::span<const uint8_t> rawData, 
        double timestamp, 
        ProtocolType firstProtocol = ProtocolType::Ethernet);
}