// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/main.cpp

// Parser
#include "parser/PcapReader.hpp"
// DPI
#include "dpi/Rule.hpp"
#include "dpi/Alert.hpp"
#include "dpi/RuleLoader.hpp"
#include "dpi/RuleEngine.hpp"
// Core
#include "core/Packet.hpp"

// Std
#include <iostream>
#include <vector>
#include <exception>
#include <format>
#include <cstddef>

namespace {
    struct ScanStats {
        std::size_t totalPackets = 0;
        std::size_t totalAlerts = 0;
        std::size_t totalLow = 0;
        std::size_t totalMedium = 0;
        std::size_t totalHigh = 0;
        std::size_t totalCritical = 0;

        void record(const Alert& alert) noexcept {
            totalAlerts++;
            switch (alert.severity) {
                case Severity::LOW:         totalLow++;         break;
                case Severity::MEDIUM:      totalMedium++;      break;
                case Severity::HIGH:        totalHigh++;        break;
                case Severity::CRITICAL:    totalCritical++;    break;
            }
        }
    };

    
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <path_to_pcap> <path_to_rules>\n";
        return 1;
    }

    try {
        RuleEngine engine(RuleLoader::loadRules(argv[2]));
        PcapReader pcap(argv[1]);

        std::cout << std::format(
            "Loaded {} rule(s). Scanning '{}'...\n\n", 
            engine.ruleCount(), 
            argv[1]
        );

        ScanStats stats;
        while (const auto packet = pcap.readNextPacket()) {
            stats.totalPackets++;
            for (const auto& alert : engine.inspect(*packet)) {
                stats.record(alert);
                std::cout << alert << "\n";
            }
        }

        std::cout << std::format(
            "--- Scan Summary ---\n"
            "Inspected {} packets.\nTriggered {} alerts with\n"
            "{} CRITICAL | {} HIGH | {} MEDIUM | {} LOW\n", 
            stats.totalPackets, stats.totalAlerts, 
            stats.totalCritical, stats.totalHigh, stats.totalMedium, stats.totalLow
        );
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}