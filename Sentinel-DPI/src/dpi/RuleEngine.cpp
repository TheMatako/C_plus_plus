// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/RuleEngine.cpp

#include "RuleEngine.hpp"
#include "../protocols/IPv4Layer.hpp"
#include "../protocols/TCPLayer.hpp"
#include "../protocols/UDPLayer.hpp"
#include "../core/ProtocolType.hpp"

#include <vector>
#include <utility>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <algorithm>
#include <string>
#include <cctype>

namespace {
    struct PacketContext {
        const IPv4Layer* ipv4;
        const TCPLayer* tcp;
        const UDPLayer* udp;
        const std::vector<uint8_t>& payload;
        std::optional<uint16_t> srcPort;
        std::optional<uint16_t> dstPort;
        ProtocolType topProtocol;
        explicit PacketContext(const Packet& packet) : 
                        ipv4(packet.getLayer<IPv4Layer>()),
                        tcp(packet.getLayer<TCPLayer>()),
                        udp(packet.getLayer<UDPLayer>()),
                        payload(packet.getPayload()) {
            if (tcp) {
                topProtocol = ProtocolType::TCP;
                srcPort = tcp->getSrcPort();
                dstPort = tcp->getDstPort();
            } else if (udp) {
                topProtocol = ProtocolType::UDP;
                srcPort = udp->getSrcPort();
                dstPort = udp->getDstPort();
            } else if (ipv4) {
                topProtocol = (ipv4->getProtocol() == IPv4Layer::PROTO_ICMP) 
                    ? ProtocolType::ICMP
                    : ProtocolType::IPv4;
            } else {
                topProtocol = ProtocolType::Ethernet;
            }
        }
    };

    bool matchesProtocol(const Rule& rule, const PacketContext& ctx) {
        if (!rule.protocol) {
            return true;
        }
        switch (*rule.protocol) {
            case ProtocolType::TCP: return ctx.tcp != nullptr;
            case ProtocolType::UDP: return ctx.udp != nullptr;
            case ProtocolType::IPv4: return ctx.ipv4 != nullptr;
            case ProtocolType::ICMP: return (ctx.ipv4 != nullptr && ctx.ipv4->getProtocol() == IPv4Layer::PROTO_ICMP);
            case ProtocolType::Ethernet: return true;
            case ProtocolType::Payload: return !ctx.payload.empty();
        }
        return false;
    }

    bool matchesIPs(const Rule& rule, const PacketContext& ctx) {
        if (!rule.srcIp && !rule.dstIp) {
            return true;
        }
        if (!ctx.ipv4) {
            return false;
        }
        if (rule.srcIp && *rule.srcIp != ctx.ipv4->getSrcIp()) {
            return false;
        } 
        if (rule.dstIp && *rule.dstIp != ctx.ipv4->getDstIp()) {
            return false;
        }
        return true;
    }

    bool matchesPorts(const Rule& rule, const PacketContext& ctx) {
        if (!rule.srcPort && !rule.dstPort) {
            return true;
        }
        if (rule.srcPort && (!ctx.srcPort || *rule.srcPort != *ctx.srcPort)) {
            return false;
        }
        if (rule.dstPort && (!ctx.dstPort || *rule.dstPort != *ctx.dstPort)) {
            return false;
        }
        return true;
    }

    bool matchesFlags(const Rule& rule, const PacketContext& ctx) {
        if (!rule.flags) {
            return true;
        }
        if (!ctx.tcp) {
            return false;
        }
        return ctx.tcp->hasFlag(*rule.flags);
    }

    bool matchesContent(const Rule& rule, const PacketContext& ctx) {
        if (!rule.content) {
            return true;
        }
        
        const std::string& pattern = *rule.content;

        if (ctx.payload.size() < pattern.size()) {
            return false;
        }

        if (rule.nocase) {
            const auto it = std::search(
                ctx.payload.begin(), ctx.payload.end(),
                pattern.begin(), pattern.end(),
                [](uint8_t payloadByte, char patternChar) {
                    return std::tolower(static_cast<unsigned char>(payloadByte)) ==
                           std::tolower(static_cast<unsigned char>(patternChar));
                }
            );
            return it != ctx.payload.end();
        }

        const auto it = std::search(
            ctx.payload.begin(), ctx.payload.end(),
            pattern.begin(), pattern.end(),
            [](uint8_t payloadByte, char patternChar) {
                return static_cast<unsigned char>(payloadByte) == static_cast<unsigned char>(patternChar);
            }
        );
        return it != ctx.payload.end();
    }
}

RuleEngine::RuleEngine(std::vector<Rule> rules) : rules_(std::move(rules)) { }

std::vector<Alert> RuleEngine::inspect(const Packet& packet) const {
    PacketContext packetContext(packet);
    std::vector<Alert> alerts;
    for (const auto& rule : rules_) {
        if (matchesProtocol(rule, packetContext) &&
            matchesIPs(rule, packetContext) &&
            matchesPorts(rule, packetContext) &&
            matchesFlags(rule, packetContext) &&
            matchesContent(rule, packetContext)) {
                alerts.emplace_back(
                    packet.getTimestamp(),
                    rule,
                    packetContext.topProtocol,
                    packetContext.ipv4 ? packetContext.ipv4->getSrcIp() : "N/A",
                    packetContext.srcPort.value_or(0),
                    packetContext.ipv4 ? packetContext.ipv4->getDstIp() : "N/A",
                    packetContext.dstPort.value_or(0)    
                );
            }
    }
    return alerts;
}   

std::size_t RuleEngine::ruleCount() const noexcept {
    return rules_.size();
}

const std::vector<Rule>& RuleEngine::getRules() const noexcept {
    return rules_;
}