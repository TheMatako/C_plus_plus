// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/TCPLayer.cpp

#include "TCPLayer.hpp"

#include <ostream>
#include <array>
#include <string_view>
#include <utility>

TCPLayer::TCPLayer(uint16_t srcPort, uint16_t dstPort, uint8_t flags, uint32_t sequence, uint32_t ack, uint8_t offset, uint16_t windows, uint16_t checksum)
: srcPort_(srcPort), dstPort_(dstPort), flags_(flags), sequence_(sequence), ack_(ack), offset_(offset), windows_(windows), checksum_(checksum) {}

uint16_t TCPLayer::getSrcPort() const {
    return srcPort_;
}
uint16_t TCPLayer::getDstPort() const {
    return dstPort_;
}
uint32_t TCPLayer::getSequence() const {
    return sequence_;
}
uint32_t TCPLayer::getAck() const {
    return ack_;
}
uint8_t TCPLayer::getOffset() const {
    return offset_;
}
uint8_t TCPLayer::getFlags() const {
    return flags_;
}
uint16_t TCPLayer::getWindows() const {
    return windows_;
}
uint16_t TCPLayer::getChecksum() const {
    return checksum_;
}

void TCPLayer::setSrcPort(uint16_t srcPort) {
    srcPort_ = srcPort;
}
void TCPLayer::setDstPort(uint16_t dstPort) {
    dstPort_ = dstPort;
}
void TCPLayer::setSequence(uint32_t sequence) {
    sequence_ = sequence;
}
void TCPLayer::setAck(uint32_t ack) {
    ack_ = ack;
}
void TCPLayer::setOffset(uint8_t offset) {
    offset_ = offset;
}
void TCPLayer::setFlags(uint8_t flags) {
    flags_ = flags;
}
void TCPLayer::setWindows(uint16_t windows) {
    windows_ = windows;
}
void TCPLayer::setChecksum(uint16_t checksum) {
    checksum_ = checksum;
}

std::string TCPLayer::getName() const {
    return "TCP";
}

bool TCPLayer::hasFlag(uint8_t flag) const {
    return (flags_ & flag) == flag;
}

void TCPLayer::print(std::ostream& os) const {
    static constexpr std::array<std::pair<uint8_t, std::string_view>, 6> flagNames = {{
            {FLAG_FIN, "FIN"}, {FLAG_SYN, "SYN"}, {FLAG_RST, "RST"},
            {FLAG_PSH, "PSH"}, {FLAG_ACK, "ACK"}, {FLAG_URG, "URG"}
        }};
    bool hasAnyFlag = false;

    
    os << "[" << getName() << "] source Port: " << srcPort_
    << " | destination Port: " << dstPort_
    << " | Flags: ";
    for (const auto& [mask, name] : flagNames) {
        if (hasFlag(mask)) {
            os << name << " ";
            hasAnyFlag = true;
        }
    }
    if (!hasAnyFlag) {
        os << "NONE ";
    }
    os << "| sequence: " << sequence_ << " | ack: " << ack_
    << " | offset: " << static_cast<int>(offset_) << " | windows: " << windows_
    << " | checksum: " << checksum_;
}