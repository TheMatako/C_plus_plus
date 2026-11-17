// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PacketParser.hpp

#pragma once

#include "../core/Packet.hpp"
#include "../core/ProtocolType.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

/// @brief Static parser that decodes a raw network frame into a stack of protocol layers
/// Currently protocols supported are: Ethernet, IPv4, TCP, and UDP (see src/core/ProtocolType.hpp for all supported protocols at this moment). 
class PacketParser {
    private:
        static ProtocolType parseEthernet(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static ProtocolType parseIPv4(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static ProtocolType parseTCP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static ProtocolType parseUDP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
    public:
        /// @brief Parses a raw byte buffer starting from an initial protocol and returns the structured Packet.
        /// @param rawData the frame to read. (std::span<const uint8_t>)
        /// @param timestamp the timestamp of the frame. (double)
        /// @param firstProtocol the first protocol expected in the frame. (ProtocolType)
        /// @return a Packet object structured with all the layers encountered.
        static Packet parse(std::span<const uint8_t> rawData, double timestamp, ProtocolType firstProtocol = ProtocolType::Ethernet);
};