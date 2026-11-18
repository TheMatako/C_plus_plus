// ========================== //
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PcapReader.cpp

#include "PcapReader.hpp"
#include "PacketParser.hpp"

#include <fstream>
#include <array>
#include <stdexcept>

PcapReader::PcapReader(const std::string& filePath) : file_(filePath, std::ios::binary) {
    if (!file_.is_open()) {
        throw std::runtime_error("File not opened successfully");
    }
    std::array<uint8_t, 24> header{};
    file_.read(reinterpret_cast<char *>(header.data()), header.size());
    if (!file_ || file_.gcount() != 24) {
        throw std::runtime_error("File not read properly");
    }

    // Reads the 4 first bytes to get endianness and timescaling of the file.
    switch ((static_cast<uint32_t>(header[0]) << 24) | (static_cast<uint32_t>(header[1]) << 16) | (static_cast<uint32_t>(header[2]) << 8) | (static_cast<uint32_t>(header[3]))) {
        case 0xD4C3B2A1: 
            isLittleEndian_ = true;
            timeScale_ = 1e6;
            break;
        case 0xA1B2C3D4:
            isLittleEndian_ = false;
            timeScale_ = 1e6;
            break;
        case 0x4D3CB2A1:
            isLittleEndian_ = true;
            timeScale_ = 1e9;
            break;
        case 0xA1B23C4D:
            isLittleEndian_ = false;
            timeScale_ = 1e9;
            break;
        default:
            throw std::runtime_error("File is not a valid .pcap");
    }

    snapLen_ = readUint32(std::span{header}.subspan<16, 4>());

    uint32_t linkType = readUint32(std::span{header}.subspan<20, 4>());
    switch (linkType) {
        case 1: 
            linkProtocol_ = ProtocolType::Ethernet;
            break;
        case 101: 
            linkProtocol_ = ProtocolType::IPv4;
            break;
        default:
            throw std::runtime_error("Unsupported link-layer protocol.");
    }
    
}

uint32_t PcapReader::readUint32(std::span<const uint8_t, 4> bytes) const {
    uint32_t block;
    if (isLittleEndian_) {
        block = (static_cast<uint32_t>(bytes[3]) << 24) | 
                (static_cast<uint32_t>(bytes[2]) << 16) |
                (static_cast<uint32_t>(bytes[1]) << 8)  |
                (static_cast<uint32_t>(bytes[0]));
    } else {
        block = (static_cast<uint32_t>(bytes[0]) << 24) | 
                (static_cast<uint32_t>(bytes[1]) << 16) |
                (static_cast<uint32_t>(bytes[2]) << 8)  |
                (static_cast<uint32_t>(bytes[3]));
    }
    return block;
}

std::optional<Packet> PcapReader::readNextPacket() {
    std::array<uint8_t, 16> pktHeader{};
    file_.read(reinterpret_cast<char *>(pktHeader.data()), pktHeader.size());

    if (file_.gcount() == 0 && file_.eof()) {
        return std::nullopt;
    } else if (!file_ || file_.gcount() != 16) {
        throw std::runtime_error("Truncated file");
    }

    uint32_t tsSec = readUint32(std::span{pktHeader}.subspan<0, 4>());
    uint32_t tsUsec = readUint32(std::span{pktHeader}.subspan<4, 4>());
    uint32_t inclLen = readUint32(std::span{pktHeader}.subspan<8, 4>());

    if (inclLen > snapLen_) {
        throw std::runtime_error("Incorrect length");
    }

    packetBuffer_.resize(inclLen);
    file_.read(reinterpret_cast<char *>(packetBuffer_.data()), inclLen);
    if (!file_ || file_.gcount() != static_cast<std::streamsize>(inclLen)) {
        throw std::runtime_error("File not read properly");
    }

    double timestamp = static_cast<double>(tsSec) + static_cast<double>(tsUsec) / timeScale_;
    return PacketParser::parse(packetBuffer_, timestamp, linkProtocol_);
}

std::vector<Packet> PcapReader::readAll() {
    std::vector<Packet> packets{};

    while (auto packet = readNextPacket()) {
        packets.push_back(std::move(*packet));
    }
    
    return packets;
}