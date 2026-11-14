// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/EthernetLayer.hpp

#pragma once

#include "ProtocolLayer.hpp"

#include <cstdint>
#include <ostream>
#include <string>

/// @brief Class extending from ProtocolLayer base class to represent the Ethernet protocol layer.
/// Contains 3 private attributes for destination MAC, source MAC, and EtherType;
class EthernetLayer : public ProtocolLayer {
    private:
        std::string dstMac_;
        std::string srcMac_;
        uint16_t etherType_; 
    public:
        // Standard Ether Types:

        static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
        static constexpr uint16_t ETHERTYPE_ARP = 0x0806;
        static constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

        EthernetLayer(std::string dstMac, std::string srcMac, uint16_t etherType);
        ~EthernetLayer() override = default;

        const std::string& getDstMac() const;
        const std::string& getSrcMac() const;
        uint16_t getEtherType() const;

        void setDstMac(std::string dstMac);
        void setSrcMac(std::string srcMac);
        void setEtherType(uint16_t etherType);

        std::string getName() const override;
        void print(std::ostream& os) const override;
};