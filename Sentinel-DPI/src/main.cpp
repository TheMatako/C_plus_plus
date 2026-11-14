// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/main.cpp

// Protocols
#include "protocols/ProtocolLayer.hpp"
#include "protocols/IPv4Layer.hpp"
#include "protocols/TCPLayer.hpp"
// Core
#include "core/Packet.hpp"


// Std
#include <iostream>
#include <memory>
#include <vector>

int main() {
    Packet packet;

    packet.addLayer(std::make_unique<IPv4Layer>("192.168.1.10", "8.8.8.8", IPv4Layer::PROTO_UDP));
    packet.addLayer(std::make_unique<IPv4Layer>("194.100.1.254", "192.168.1.10", IPv4Layer::PROTO_TCP, 128));
    packet.addLayer(std::make_unique<TCPLayer>(8080, 80, TCPLayer::FLAG_SYN | TCPLayer::FLAG_ACK));
    packet.setPayload({0x48, 0x54, 0x54, 0x50});
    std::cout << packet;

    return 0;
}