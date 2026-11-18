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
#include "parser/PcapReader.hpp"
// Core
#include "core/Packet.hpp"

// Std
#include <iostream>
#include <memory>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_pcap>\n";
        return 1;
    }

    try {
        PcapReader pcap(argv[1]);
        std::vector<Packet> packets = pcap.readAll();

        for (const auto& packet : packets) {
            std::cout << packet << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}