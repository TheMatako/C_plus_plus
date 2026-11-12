// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/IPv4Layer.cpp

#include "IPv4Layer.hpp"

#include <utility>

IPv4Layer::IPv4Layer(std::string srcIp, std::string dstIp, uint8_t protocol, uint8_t ttl)
    : srcIp_(std::move(srcIp)), dstIp_(std::move(dstIp)), protocol_(protocol), ttl_(ttl) {}

std::string IPv4Layer::getSrcIp() const {
    return srcIp_;
}

std::string IPv4Layer::getDstIp() const {
    return dstIp_;
}

uint8_t IPv4Layer::getProtocol() const {
    return protocol_;
}

uint8_t IPv4Layer::getTtl() const {
    return ttl_;
}

void IPv4Layer::setSrcIp(std::string srcIp) {
    srcIp_ = std::move(srcIp);
}

void IPv4Layer::setDstIp(std::string dstIp) {
    dstIp_ = std::move(dstIp);
}

void IPv4Layer::setProtocol(uint8_t protocol) {
    protocol_ = protocol;
}

void IPv4Layer::setTtl(uint8_t ttl) {
    ttl_ = ttl;
}

std::string IPv4Layer::getName() const {
    return "IPv4";
}

void IPv4Layer::print(std::ostream& os) const {
    os << "[" << getName() << "] source IP: " << srcIp_ 
    << " | destination IP: " << dstIp_ 
    << " | protocol: " << static_cast<int>(protocol_) 
    << " | ttl: " << static_cast<int>(ttl_);
}