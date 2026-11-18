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

    Alert(double timestamp_, const Rule& rule, ProtocolType protocol_, std::string srcIp_, uint16_t srcPort_, std::string dstIp_, uint16_t dstPort_);
};

std::ostream& operator<<(std::ostream& os, const Alert& alert);
