// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/Alert.cpp

#include "Alert.hpp"

#include <chrono>
#include <format>
#include <utility>

Alert::Alert(double timestamp_, const Rule& rule, ProtocolType protocol_, std::string srcIp_, uint16_t srcPort_, std::string dstIp_, uint16_t dstPort_) : 
    timestamp(timestamp_), sid(rule.sid), msg(rule.msg), 
    severity(rule.severity), protocol(protocol_), srcIp(std::move(srcIp_)), 
    srcPort(srcPort_), dstIp(std::move(dstIp_)), dstPort(dstPort_) {}

std::ostream& operator<<(std::ostream& os, const Alert& alert) {
    auto alertTime = std::chrono::zoned_time{std::chrono::current_zone(), std::chrono::sys_time<std::chrono::microseconds>{{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::duration<double>{alert.timestamp})}}};

    os << "[ALERT " << severityToString(alert.severity) << "] Matches rule number "
    << alert.sid << ": " << alert.msg << ".\n" << "Time: " 
    << std::format("{:%d/%m/%Y %H:%M:%S}", alertTime) << " | Protocol used: "
    << alert.protocol << "\nSource IP: " << alert.srcIp << " | Source Port: "
    << alert.srcPort << " | Destination IP: " << alert.dstIp 
    << " | Destination Port: " << alert.dstPort << ".\n";

    return os;
}