// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/IPv4Layer.hpp

#pragma once

#include "ProtocolLayer.hpp"

#include <ostream>
#include <string>
#include <cstdint>

/// @brief Class extending from ProtocolLayer base class to represent the IPv4 protocol layer.
/// Contains 4 private attributes for IP source, IP destination, Protocol encapsulated and Time to live (TTL).
class IPv4Layer : public ProtocolLayer {
    private:
        std::string srcIp_;
        std::string dstIp_;
        uint8_t protocol_;
        uint8_t ttl_;
    public:
        // Standard IANA IPv4 protocol number.
        
        static constexpr uint8_t PROTO_ICMP = 1;
        static constexpr uint8_t PROTO_TCP = 6;
        static constexpr uint8_t PROTO_UDP = 17;
        

        IPv4Layer(std::string srcIp, std::string dstIp, uint8_t protocol, uint8_t ttl = 64);
        ~IPv4Layer() override = default;

        std::string getSrcIp() const;
        std::string getDstIp() const;
        uint8_t getProtocol() const;
        uint8_t getTtl() const;

        void setSrcIp(std::string srcIp);
        void setDstIp(std::string dstIp);
        void setProtocol(uint8_t protocol);
        void setTtl(uint8_t ttl);

        std::string getName() const override;
        void print(std::ostream& os) const override;
};