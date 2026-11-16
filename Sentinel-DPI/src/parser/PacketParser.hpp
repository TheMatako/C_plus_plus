// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PackerParser.hpp

#pragma once

#include "../core/Packet.hpp"

#include <string_view>
#include <cstddef>
#include <cstdint>
#include <string>
#include <span>

/// @brief Static parser that decodes a raw network frame into a stack of protocol layers
/// Currently protocols supported are: Ethernet, IPv4, TCP, and UDP. 
class PacketParser {
    private:
        static std::string parseEthernet(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static std::string parseIPv4(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static std::string parseTCP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
        static std::string parseUDP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset);
    public:
        /// @brief Parses a raw byte buffer starting from an initial protocol and returns the structured Packet.
        /// @param rawData the frame to read. (std::span<const uint8_t>)
        /// @param timestamp the timestamp of the frame. (double)
        /// @param firstProtocol the first protocol expected in the frame. (string)
        /// @return a Packet object structured with all the layers encountered.
        static Packet parse(std::span<const uint8_t> rawData, double timestamp, std::string_view firstProtocol = "Ethernet");
};