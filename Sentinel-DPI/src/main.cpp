// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/main.cpp

// Protocols
#include "protocols/ProtocolLayer.hpp"
#include "protocols/IPv4Layer.hpp"
#include "protocols/TCPLayer.hpp"
#include "protocols/EthernetLayer.hpp"
#include "protocols/UDPLayer.hpp"
// Parser
#include "parser/PacketParser.hpp"
// Core
#include "core/Packet.hpp"

// Std
#include <iostream>
#include <memory>
#include <vector>

int main() {

    // Raw frame : Ethernet (14) + IPv4 (20) + TCP (20) + Payload "HELLO" (5) = 59 bytes
    std::vector<uint8_t> rawFrame = {
        // --- Ethernet ---
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC destination: AA:BB:CC:DD:EE:FF
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // MAC source: 11:22:33:44:55:66
        0x08, 0x00,                         // EtherType: 0x0800 (IPv4)
        
        // --- IPv4 ---
        0x45, 0x00,                         // Version 4, IHL 5 (20 bytes), DSCP/ECN 0
        0x00, 0x2D,                         // Total Length: 45 bytes (20 IP + 20 TCP + 5 Payload)
        0x12, 0x34, 0x40, 0x00,             // Identification + flags(DF) + fragment offset
        0x40,                               // TTL: 64
        0x06,                               // Protocol: 6 (TCP)
        0x00, 0x00,                         // Header checksum
        0xC0, 0xA8, 0x01, 0x0A,             // IP source: 192.168.1.10
        0x5D, 0xB8, 0xD8, 0x22,             // IP destination: 93.184.216.32

        // --- TCP ---
        0xD4, 0x31,                         // Port source: 54321
        0x00, 0x50,                         // Port destination: 80 (HTTP) 
        0x00, 0x00, 0x03, 0xE8,             // Sequence: 1000
        0x00, 0x00, 0x00, 0x01,             // Ack: 1
        0x50,                               // Data offset: 5 (20 bytes)
        0x18,                               // Flags: PSH (0x08) | ACK (0x10)
        0xFF, 0xFF,                         // Window: 65535
        0x1A, 0x2B,                         // Checksum: 0x1A2B (6699)
        0x00, 0x00,                         // Urgent Pointer: 0

        // --- Payload ---
        0x48, 0x45, 0x4C, 0x4C, 0x4F        // "HELLO"
    };
    Packet packet = PacketParser::parse(rawFrame, 1700000000.123);

    std::cout << packet << "\n";
    
    const auto& payload = packet.getPayload();
    std::string text(payload.begin(), payload.end());
    std::cout << "Payload (" << payload.size() << " bytes): " << text << "\n";
    return 0;
}