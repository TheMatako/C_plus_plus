// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/dpi/RuleLoader.cpp

#include "RuleLoader.hpp"

#include <fstream>
#include <stdexcept>
#include <string_view>
#include <cstddef>
#include <format>
#include <vector>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <algorithm>
#include <concepts>

namespace {

    template <std::unsigned_integral T>
    std::optional<T> parseUnsigned(std::string_view sv) noexcept {
        T value = 0;
        const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
        if (ptr != (sv.data() + sv.size()) || ec != std::errc{}) {
            return std::nullopt;
        }
        return value;
    }

    std::vector<std::string_view> split(std::string_view sv, std::string_view splitChars) {
        std::vector<std::string_view> tokens;

        while (!sv.empty()) {
            const auto start = sv.find_first_not_of(splitChars);
            if (start == std::string_view::npos) {
                break;
            }
            sv.remove_prefix(start);

            const auto end = sv.find_first_of(splitChars);
            if (end == std::string_view::npos) {
                tokens.push_back(sv);
                break;
            }
            tokens.push_back(sv.substr(0, end));
            sv.remove_prefix(end);
        }
        return tokens;
    }
    
    constexpr std::string_view trim(std::string_view sv) noexcept {
        constexpr std::string_view whitespace = " \t\r\n";
        const auto first = sv.find_first_not_of(whitespace);
        if (first == std::string_view::npos) {
            return {};
        }
        const auto last = sv.find_last_not_of(whitespace);
        return sv.substr(first, last - first + 1);
    }

    std::optional<ProtocolType> parseProtocol(std::string_view protocol, std::size_t lineNumber) {
        if (protocol == "ip" || protocol == "ipv4") return ProtocolType::IPv4;
        if (protocol == "icmp") return ProtocolType::ICMP;
        if (protocol == "tcp") return ProtocolType::TCP;
        if (protocol == "udp") return ProtocolType::UDP;
        if (protocol == "any") return std::nullopt;
        throw std::runtime_error(std::format("Line {}: Unsupported protocol '{}'.", lineNumber, protocol));
    }

    std::optional<std::string> parseIp(std::string_view ip, std::size_t lineNumber) {
        if (ip == "any") {
            return std::nullopt;
        }
        std::vector<std::string_view> ips = split(ip, ".");
        if (ips.size() != 4 || std::ranges::count(ip, '.') != 3) {
            throw std::runtime_error(std::format("Line {}: Invalid IP format for IP: '{}'.", lineNumber, ip));
        }
        for (int i = 0; i < 4; i++) {
            if (ips[i].size() > 1 && ips[i].front() == '0') {
                throw std::runtime_error(std::format("Line {}: Invalid IP format for IP: '{}'.", lineNumber, ip));
            }
            if (!parseUnsigned<uint8_t>(ips[i])) {
                throw std::runtime_error(std::format("Line {}: Invalid IP format for IP: '{}'.", lineNumber, ip));
            }
        }
        return std::string(ip);
    }

    std::optional<uint16_t> parsePort(std::string_view port, std::size_t lineNumber) {
        if (port == "any") {
            return std::nullopt;   
        }
        const auto value = parseUnsigned<uint16_t>(port);
        if (!value || *value == 0) {
            throw std::runtime_error(std::format("Line {}: Invalid Port format for Port: '{}'.", lineNumber, port));
        }
        return value;
    }    

    std::vector<std::string_view> splitOptions(std::string_view sv, std::size_t lineNumber) {
        std::vector<std::string_view> options;
        bool inQuotes = false;
        std::size_t start = 0;
        for (std::size_t i = 0; i < sv.size(); i++) {
            if (sv[i] == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes && sv[i] == ';') {
                auto opt = trim(sv.substr(start, i - start));
                if (!opt.empty()) {
                    options.push_back(opt);
                }
                start = i + 1;
            }
        }
        if (inQuotes) {
            throw std::runtime_error(std::format("Line {}: Invalid options format with options: '{}'.", lineNumber, sv));
        }
        if (!(trim(sv.substr(start))).empty()) {
            throw std::runtime_error(std::format("Line {}: Invalid options format, missing final ';'.", lineNumber));
        }
        return options;
    }

    std::string_view unquote(std::string_view sv, std::size_t lineNumber) {
        if (sv.size() < 2 || sv.front() != '"' || sv.back() != '"') {
            throw std::runtime_error(std::format("Line {}: Invalid option format with option: {}.", lineNumber, sv));
        }
        return sv.substr(1, sv.size() - 2);
    }

    Severity parseSeverity(std::string_view value, std::size_t lineNumber) {
        if (value == "low") return Severity::LOW;
        if (value == "medium") return Severity::MEDIUM;
        if (value == "high") return Severity::HIGH;
        if (value == "critical") return Severity::CRITICAL;
        throw std::runtime_error(std::format("Line {}: Invalid severity option: {}.", lineNumber, value));
    }

    uint8_t parseTcpFlags(std::string_view value, std::size_t lineNumber) {
        uint8_t mask = 0;
        if (value.empty()) {
            throw std::runtime_error(std::format("Line {}: Empty TCP flags option.", lineNumber));
        }
        for (char c : value) {
            switch (c) {
                case 'F': 
                    mask |= 0x01;
                    break;
                case 'S': 
                    mask |= 0x02;
                    break;
                case 'R': 
                    mask |= 0x04;
                    break;
                case 'P':
                    mask |= 0x08;
                    break;
                case 'A':
                    mask |= 0x10;
                    break;
                case 'U':
                    mask |= 0x20;
                    break;
                default:
                    throw std::runtime_error(std::format("Line {}: Invalid TCP flag: '{}'.", lineNumber, c));
            }
        }
        return mask;
    }

}

namespace {
    
    void parseHeader(std::string_view line, std::size_t lineNumber, Rule& rule) {
        std::vector<std::string_view> words = split(line, " \t");
        if (words.size() != 7) {
            throw std::runtime_error(std::format("Line {}: Expected 7 header tokens, got {}.", lineNumber, words.size()));
        }
        if (words[0] != "alert") {
            throw std::runtime_error(std::format("Line {}: Unsupported action '{}'.", lineNumber, words[0]));
        }
        if (words[4] != "->") {
            throw std::runtime_error(std::format("Line {}: Expected '->' direction, got '{}'.", lineNumber, words[4]));
        }
        rule.protocol = parseProtocol(words[1], lineNumber);
        rule.srcIp = parseIp(words[2], lineNumber);
        rule.srcPort = parsePort(words[3], lineNumber);
        rule.dstIp = parseIp(words[5], lineNumber);
        rule.dstPort = parsePort(words[6], lineNumber);
    }

    void parseOptions(std::string_view line, std::size_t lineNumber, Rule& rule) {
        std::vector<std::string_view> options = splitOptions(line, lineNumber);
        bool hasSid = false;
        bool hasMsg = false;

        for (const auto option : options) {
            const auto colon = option.find(':');
            if (colon == std::string_view::npos) {
                if (option == "nocase") {
                    rule.nocase = true;
                    continue;
                } else {
                    throw std::runtime_error(std::format("Line {}: Invalid options format with option '{}'.", lineNumber, option));
                }
            }
            const auto key = trim(option.substr(0, colon));
            const auto value = trim(option.substr(colon + 1));
            if (key == "msg") {
                std::string_view unquoted = unquote(value, lineNumber);
                if (unquoted.empty()) {
                    throw std::runtime_error(std::format("Line {}: Invalid message option: '{}'.", lineNumber, unquoted));
                }
                if (hasMsg) {
                    throw std::runtime_error(std::format("Line {}: Multiple message option encountered.", lineNumber));
                }
                rule.msg = unquoted;
                hasMsg = true;
            } else if (key == "content") {
                std::string_view unquoted = unquote(value, lineNumber);
                if (unquoted.empty()) {
                    throw std::runtime_error(std::format("Line {}: Invalid content option: '{}'", lineNumber, unquoted));
                }
                rule.content.emplace(unquoted);

            } else if (key == "sid") {
                if (hasSid) {
                    throw std::runtime_error(std::format("Line {}: Multiple sid option encountered.", lineNumber));
                }
                const auto sid = parseUnsigned<uint32_t>(value);          
                if (!sid || *sid == 0) {
                    throw std::runtime_error(std::format("Line {}: Invalid format for SID: '{}'.", lineNumber, value));
                }
                rule.sid = *sid;
                hasSid = true;
            } else if (key == "severity") {
                rule.severity = parseSeverity(value, lineNumber);
            } else if (key == "flags") {
                rule.flags = parseTcpFlags(value, lineNumber);
            } else {
                throw std::runtime_error(std::format("Line {}: Unknown option: '{}'.", lineNumber, key));
            }
        }
        if (!hasSid) {
            throw std::runtime_error(std::format("Line {}: Missing required option 'sid'.", lineNumber));
        }
        if (!hasMsg) {
            throw std::runtime_error(std::format("Line {}: Missing required option 'msg'.", lineNumber));
        }
    }

    Rule parseLine(std::string_view line, std::size_t lineNumber) {
        Rule rule;
        const auto openParen = line.find('(');
        const auto closeParen = line.rfind(')');
        if ((openParen == std::string_view::npos) || (closeParen == std::string_view::npos) ||
                (openParen >= closeParen) || (closeParen != line.size() - 1)) {
            throw std::runtime_error(std::format("Line {}: Invalid rule", lineNumber));
        }
        parseHeader(trim(line.substr(0, openParen)), lineNumber, rule);
        parseOptions(trim(line.substr(openParen + 1, closeParen - openParen - 1)), lineNumber, rule);
        return rule;
    }

}


namespace RuleLoader {
    
    std::vector<Rule> loadRules(const std::string& filePath) {
        std::ifstream file(filePath); 
        if (!file.is_open()) {
            throw std::runtime_error(std::format("Cannot open rules file: {}.",filePath));
        }

        std::vector<Rule> rules;
        std::string line; 
        std::size_t lineNumber = 0;
        while (std::getline(file, line)) {
            lineNumber++;
            const std::string_view trimmed = trim(line);
            if (trimmed.empty() || trimmed.starts_with('#')) {
                continue;
            }
            rules.push_back(parseLine(trimmed, lineNumber));
        }
        return rules;
    }

}