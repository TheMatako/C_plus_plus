// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/main.cpp

#include "protocols/IPv4Layer.hpp"
#include "protocols/ProtocolLayer.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main() {

    std::vector<std::unique_ptr<ProtocolLayer>> layers;

    layers.push_back(std::make_unique<IPv4Layer>("192.168.1.10", "8.8.8.8", IPv4Layer::PROTO_UDP));
    layers.push_back(std::make_unique<IPv4Layer>("194.100.1.254", "192.168.1.10", IPv4Layer::PROTO_TCP, 128));

    for (const auto& layer : layers) {
        std::cout << *layer << "\n";
    }

    return 0;
}