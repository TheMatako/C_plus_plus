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
#include "protocols/UDPLayer.hpp"
// Parser
#include "parser/PacketParser.hpp"
#include "parser/PcapReader.hpp"
// DPI
#include "dpi/Rule.hpp"
#include "dpi/Alert.hpp"
#include "dpi/RuleLoader.hpp"
// Core
#include "core/Packet.hpp"

// Std
#include <cstdint>
#include <iostream>
#include <vector>
#include <exception>
#include <format>
#include <string>

namespace {
    std::string tcpFlagsToString(uint8_t mask) {
        std::string flags;
        if (mask & 0x01) flags += 'F';
        if (mask & 0x02) flags += 'S';
        if (mask & 0x04) flags += 'R';
        if (mask & 0x08) flags += 'P';
        if (mask & 0x10) flags += 'A';
        if (mask & 0x20) flags += 'U';
        return std::format("{} (0x{:02X})", flags.empty() ? "none" : flags, mask);
    }

    void printRule(const Rule& rule) {
        const std::string proto = rule.protocol ? std::string(protocolToString(*rule.protocol)) : "any";
        const std::string srcIp = rule.srcIp.value_or("any");
        const std::string srcPort = rule.srcPort ? std::to_string(*rule.srcPort) : "any";
        const std::string dstIp = rule.dstIp.value_or("any");
        const std::string dstPort = rule.dstPort ? std::to_string(*rule.dstPort) : "any";
        const std::string flags = rule.flags ? tcpFlagsToString(*rule.flags) : "any";
        const std::string content = rule.content
            ? std::format("\"{}\"{}", *rule.content, rule.nocase ? " (nocase)" : "")
            : "none";

        std::cout << std::format(
            "[SID {}] [{}] {} {}:{} -> {}:{} | msg: \"{}\" | flags: {} | content: {}\n",
            rule.sid,
            severityToString(rule.severity),
            proto,
            srcIp, srcPort,
            dstIp, dstPort,
            rule.msg,
            flags,
            content
        );
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_rules>\n";
        return 1;
    }

    try {
        std::vector<Rule> rules = RuleLoader::loadRules(argv[1]);
        std::cout << std::format("Loaded {} rule(s):\n", rules.size());
        
        for (const auto& rule : rules) {
            printRule(rule);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}