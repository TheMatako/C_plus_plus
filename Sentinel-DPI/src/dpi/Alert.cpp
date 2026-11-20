// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/Alert.cpp

#include "Alert.hpp"

#include <chrono>
#include <format>
#include <utility>

Alert::Alert(double ts, const Rule& rule, ProtocolType proto, std::string sourceIp, uint16_t sourcePort, std::string destinationIp, uint16_t destinationPort) : 
    timestamp(ts), sid(rule.sid), msg(rule.msg), 
    severity(rule.severity), protocol(proto), srcIp(std::move(sourceIp)), 
    srcPort(sourcePort), dstIp(std::move(destinationIp)), dstPort(destinationPort) {}

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