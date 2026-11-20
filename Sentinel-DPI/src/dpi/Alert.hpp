// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/Alert.hpp

#pragma once

#include "Rule.hpp"

#include <ostream>
#include <string>
#include <cstdint>

struct Alert {
    double timestamp;
    uint32_t sid;
    std::string msg;
    Severity severity;
    ProtocolType protocol;
    std::string srcIp;
    uint16_t srcPort;
    std::string dstIp;
    uint16_t dstPort;

    Alert(double ts, const Rule& rule, ProtocolType proto, std::string sourceIp, uint16_t sourcePort, std::string destinationIp, uint16_t destinationPort);
};

std::ostream& operator<<(std::ostream& os, const Alert& alert);
