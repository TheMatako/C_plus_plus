// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/UDPLayer.hpp

#pragma once

#include "ProtocolLayer.hpp"

#include <ostream>
#include <string>
#include <cstdint>

/// @brief Class extending from ProtocolLayer base class to represent the UDP protocol layer.
/// Contains 4 private attributes for source Port, destination Port, length, and checksum.
class UDPLayer : public ProtocolLayer {
    private:
        uint16_t srcPort_;
        uint16_t dstPort_;
        uint16_t length_;
        uint16_t checksum_;
    public:

        UDPLayer(uint16_t srcPort, uint16_t dstPort, uint16_t length = 8, uint16_t checksum = 0);
        ~UDPLayer() override = default;

        uint16_t getSrcPort() const;
        uint16_t getDstPort() const;
        uint16_t getLength() const;
        uint16_t getChecksum() const;

        void setSrcPort(uint16_t srcPort);
        void setDstPort(uint16_t dstPort);
        void setLength(uint16_t length);
        void setChecksum(uint16_t checksum);

        std::string getName() const override;
        void print(std::ostream& os) const override;
};