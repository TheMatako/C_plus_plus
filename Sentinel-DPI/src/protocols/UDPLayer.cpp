// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/UDPLayer.cpp

#include "UDPLayer.hpp"

UDPLayer::UDPLayer(uint16_t srcPort, uint16_t dstPort, uint16_t length, uint16_t checksum)
    : srcPort_(srcPort), dstPort_(dstPort), length_(length), checksum_(checksum) {}

uint16_t UDPLayer::getSrcPort() const {
    return srcPort_;
}

uint16_t UDPLayer::getDstPort() const {
    return dstPort_;
}

uint16_t UDPLayer::getLength() const {
    return length_;
}

uint16_t UDPLayer::getChecksum() const {
    return checksum_;
}

void UDPLayer::setSrcPort(uint16_t srcPort) {
    srcPort_ = srcPort;
}

void UDPLayer::setDstPort(uint16_t dstPort) {
    dstPort_ = dstPort;
}

void UDPLayer::setLength(uint16_t length) {
    length_ = length;
}

void UDPLayer::setChecksum(uint16_t checksum) {
    checksum_ = checksum;
}

std::string UDPLayer::getName() const {
    return "UDP";
}

void UDPLayer::print(std::ostream& os) const {
    os << "[" << getName() << "] source Port: " << srcPort_
    << " | destination Port: " << dstPort_
    << " | length: " << length_
    << " | checksum: " << checksum_;
}
