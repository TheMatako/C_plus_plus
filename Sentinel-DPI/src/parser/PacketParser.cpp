// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/parser/PackerParser.cpp

#include "PacketParser.hpp"
#include "../protocols/EthernetLayer.hpp"
#include "../protocols/UDPLayer.hpp"
#include "../protocols/TCPLayer.hpp"
#include "../protocols/IPv4Layer.hpp"

#include <memory>

Packet PacketParser::parse(std::span<const uint8_t> rawData, double timestamp, std::string_view firstProtocol) {
    Packet packet(timestamp);
    std::string_view protocol = firstProtocol;
    std::size_t offset = 0;

    while (protocol != "Payload" && offset < rawData.size()) {
        if (protocol == "Ethernet") {
            protocol = parseEthernet(rawData.subspan(offset), packet, offset);
        } else if (protocol == "IPv4") {
            protocol = parseIPv4(rawData.subspan(offset), packet, offset);
        } else if (protocol == "TCP") {
            protocol = parseTCP(rawData.subspan(offset), packet, offset);
        } else if (protocol == "UDP") {
            protocol = parseUDP(rawData.subspan(offset), packet, offset);
        } else {
            protocol = "Payload";
        }
    }
    auto remaining = rawData.subspan(offset);
    packet.setPayload({remaining.begin(), remaining.end()});
    return packet;
}

std::string PacketParser::parseEthernet(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset) {
    
    if (rawData.size() < 14) {
        return "Payload";
    }

    constexpr char hexChars[] = "0123456789ABCDEF";
    std::string dstMac;
    std::string srcMac;
    dstMac.reserve(17);
    srcMac.reserve(17);

    for (int i = 0; i < 6; i++) {
        dstMac += hexChars[(rawData[i] >> 4) & 0x0F];
        dstMac += hexChars[rawData[i] & 0x0F];
        srcMac += hexChars[(rawData[6 + i] >> 4) & 0x0F];
        srcMac += hexChars[rawData[6 + i] & 0x0F];
        
        if (i < 5) {
            dstMac += ":";
            srcMac += ":";
        }
    }

    uint16_t etherType = static_cast<uint16_t>(rawData[12]) << 8 | rawData[13];
    packet.addLayer(std::make_unique<EthernetLayer>(dstMac, srcMac, etherType));
    offset += 14;

    switch (etherType) {
        case EthernetLayer::ETHERTYPE_IPV4: return "IPv4";
        default:                            return "Payload";
    }
}

std::string PacketParser::parseUDP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset) {
    if (rawData.size() < 8) {
        return "Payload";
    }

    uint16_t srcPort = static_cast<uint16_t>(rawData[0]) << 8 | rawData[1];
    uint16_t dstPort = static_cast<uint16_t>(rawData[2]) << 8 | rawData[3];
    uint16_t length = static_cast<uint16_t>(rawData[4]) << 8 | rawData[5];
    uint16_t checksum = static_cast<uint16_t>(rawData[6]) << 8 | rawData[7];
    packet.addLayer(std::make_unique<UDPLayer>(srcPort, dstPort, length, checksum));
    offset += 8;
    return "Payload";
}

std::string PacketParser::parseIPv4(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset) {
    if (rawData.size() < 20) {
        return "Payload";
    }
    std::size_t length = 4*(rawData[0] & 0x0F);
    if (length < 20 || length > 60 || rawData.size() < length) {
        return "Payload";
    }
    std::string srcIp = std::to_string(rawData[12]) + "." +
                        std::to_string(rawData[13]) + "." +
                        std::to_string(rawData[14]) + "." +
                        std::to_string(rawData[15]);

    std::string dstIp = std::to_string(rawData[16]) + "." +
                        std::to_string(rawData[17]) + "." +
                        std::to_string(rawData[18]) + "." +
                        std::to_string(rawData[19]);
    uint8_t protocol = rawData[9];
    uint8_t ttl = rawData[8];
    
    packet.addLayer(std::make_unique<IPv4Layer>(srcIp, dstIp, protocol, ttl));
    offset += length;

    switch (protocol) {
        case IPv4Layer::PROTO_ICMP: return "ICMP";
        case IPv4Layer::PROTO_TCP:  return "TCP";
        case IPv4Layer::PROTO_UDP:  return "UDP";
        default:                    return "Payload";
    }
}

std::string PacketParser::parseTCP(std::span<const uint8_t> rawData, Packet& packet, std::size_t& offset) {
    if (rawData.size() < 20) {
        return "Payload";
    }
    std::size_t length = 4*(rawData[12] >> 4 & 0x0F);
    if (length < 20 || length > 60 || rawData.size() < length) {
        return "Payload";
    }
    
    uint16_t srcPort = (static_cast<uint16_t>(rawData[0]) << 8) | rawData[1];
    uint16_t dstPort = (static_cast<uint16_t>(rawData[2]) << 8) | rawData[3];
    uint32_t sequence = (static_cast<uint32_t>(rawData[4]) << 24) |
                        (static_cast<uint32_t>(rawData[5]) << 16) |
                        (static_cast<uint32_t>(rawData[6]) << 8) |
                        static_cast<uint32_t>(rawData[7]);
    uint32_t ack =  (static_cast<uint32_t>(rawData[8]) << 24) |
                    (static_cast<uint32_t>(rawData[9]) << 16) |
                    (static_cast<uint32_t>(rawData[10]) << 8) |
                    static_cast<uint32_t>(rawData[11]);
    uint8_t dataOffset = (rawData[12] >> 4) & 0x0F;
    uint8_t flags = rawData[13];
    uint16_t windows = (static_cast<uint16_t>(rawData[14]) << 8) | rawData[15]; 
    uint16_t checksum = (static_cast<uint16_t>(rawData[16]) << 8) | rawData[17]; 

    packet.addLayer(std::make_unique<TCPLayer>(srcPort, dstPort, flags, sequence, ack, dataOffset, windows, checksum));
    offset += length;

    return "Payload";
}