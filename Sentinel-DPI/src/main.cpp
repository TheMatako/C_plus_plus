// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/main.cpp

#include "protocols/IPv4Layer.hpp"
#include "protocols/ProtocolLayer.hpp"
#include "core/Packet.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main() {
    Packet packet;

    packet.addLayer(std::make_unique<IPv4Layer>("192.168.1.10", "8.8.8.8", IPv4Layer::PROTO_UDP));
    packet.addLayer(std::make_unique<IPv4Layer>("194.100.1.254", "192.168.1.10", IPv4Layer::PROTO_TCP, 128));
    packet.setPayload({0x48, 0x54, 0x54, 0x50});
    std::cout << packet;

    return 0;
}