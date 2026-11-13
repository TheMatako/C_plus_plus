// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/core/Packet.cpp

#include "Packet.hpp"

#include <utility>

Packet::Packet(double timestamp) : timestamp_(timestamp) { }

void Packet::addLayer(std::unique_ptr<ProtocolLayer> layer) {
    layers_.push_back(std::move(layer));
}

void Packet::setPayload(std::vector<uint8_t> payload) {
    payload_ = std::move(payload);
}

const std::vector<uint8_t>& Packet::getPayload() const {
    return payload_;
}

const std::vector<std::unique_ptr<ProtocolLayer>>& Packet::getLayers() const {
    return layers_;
}

std::size_t Packet::layerCount() const {
    return layers_.size();
}

double Packet::getTimestamp() const {
    return timestamp_;
}

std::ostream& operator<<(std::ostream& os, const Packet& packet) {
    os << "Packet: timestamp = " << packet.getTimestamp() << ", layer counts : " << packet.layerCount();
    for (const auto& layer : packet.getLayers()) {
        os << "\n - " << *layer;
    }
    os << "\nPayload size: " << packet.getPayload().size() << "\n";
    return os;
}

