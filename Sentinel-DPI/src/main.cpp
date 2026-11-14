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
// Core
#include "core/Packet.hpp"


// Std
#include <iostream>
#include <memory>
#include <vector>

int main() {
    Packet packet;
    
    packet.addLayer(std::make_unique<EthernetLayer>("02:42:AC:11:00:02", "3A:7F:91:C4:B8:19", EthernetLayer::ETHERTYPE_IPV4));
    packet.addLayer(std::make_unique<IPv4Layer>("192.168.1.10", "8.8.8.8", IPv4Layer::PROTO_UDP));
    packet.addLayer(std::make_unique<TCPLayer>(8080, 80, TCPLayer::FLAG_SYN | TCPLayer::FLAG_ACK));
    packet.setPayload({0x48, 0x54, 0x54, 0x50});
    std::cout << packet;

    return 0;
}