// ========================== //
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PcapReader.hpp

#pragma once

#include "../core/Packet.hpp"
#include "../core/ProtocolType.hpp"

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>
#include <span>

/// @brief Streaming reader for binary .pcap capture files.
/// Takes a file path in argument. Has readAll() method to return a std::vector<Packet>
/// of all the different packets in the .pcap file given.
class PcapReader {
private:
    std::ifstream file_;
    std::vector<uint8_t> packetBuffer_;
    bool isLittleEndian_ = true;
    double timeScale_ = 1e6;
    uint32_t snapLen_ = 65535;
    ProtocolType linkProtocol_ = ProtocolType::Ethernet;

    /// @brief Arranges 4 bytes in a uint32_t following the value of isLittleEndian_
    /// @param bytes the 4 bytes to arrange
    /// @return a 4 bytes long arranged int 
    uint32_t readUint32(std::span<const uint8_t, 4> bytes) const;

public:
    explicit PcapReader(const std::string& filePath);

    
    std::optional<Packet> readNextPacket();
    std::vector<Packet> readAll();
};