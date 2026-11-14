// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/EthernetLayer.cpp

#include "EthernetLayer.hpp"

#include <iomanip>
#include <ostream>
#include <utility>

EthernetLayer::EthernetLayer(std::string dstMac, std::string srcMac, uint16_t etherType)
    : dstMac_(std::move(dstMac)), srcMac_(std::move(srcMac)), etherType_(etherType) {}

const std::string& EthernetLayer::getDstMac() const {
    return dstMac_;
}

const std::string& EthernetLayer::getSrcMac() const {
    return srcMac_;
}

uint16_t EthernetLayer::getEtherType() const {
    return etherType_;
}

void EthernetLayer::setDstMac(std::string dstMac) {
    dstMac_ = std::move(dstMac);
}

void EthernetLayer::setSrcMac(std::string srcMac) {
    srcMac_ = std::move(srcMac);
}

void EthernetLayer::setEtherType(uint16_t etherType) {
    etherType_ = etherType;
}

std::string EthernetLayer::getName() const {
    return "Ethernet";
}

void EthernetLayer::print(std::ostream& os) const {
    os << "[" << getName() << "] destination MAC: " << dstMac_
    << " | source MAC: " << srcMac_
    << " | ethernet Type: 0x" << std::hex << std::setw(4) << std::setfill('0') << etherType_ << std::dec;
}