// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/TCPLayer.hpp

#pragma once

#include "ProtocolLayer.hpp"

#include <cstdint>


/// @brief Class extending from ProtocolLayer base class to represent the TCP protocol layer.
/// Contains 8 private attributes for Port source, Port destination, Sequence, Ack, Offset, Flags, Windows, and Checksum.
class TCPLayer : public ProtocolLayer {
    private:
        uint16_t srcPort_;
        uint16_t dstPort_;
        uint8_t flags_;
        uint32_t sequence_;
        uint32_t ack_;
        uint8_t offset_;
        uint16_t windows_;
        uint16_t checksum_;
    public:
        // Standard TCP flags
        
        static constexpr uint8_t FLAG_FIN = 0x01;
        static constexpr uint8_t FLAG_SYN = 0x02;
        static constexpr uint8_t FLAG_RST = 0x04;
        static constexpr uint8_t FLAG_PSH = 0x08;
        static constexpr uint8_t FLAG_ACK = 0x10;
        static constexpr uint8_t FLAG_URG = 0x20;

        TCPLayer(uint16_t srcPort, uint16_t dstPort, uint8_t flags, uint32_t sequence = 0, uint32_t ack = 0, uint8_t offset = 0, uint16_t windows = 0, uint16_t checksum = 0);
        ~TCPLayer() override = default;

        uint16_t getSrcPort() const;
        uint16_t getDstPort() const;
        uint32_t getSequence() const;
        uint32_t getAck() const;
        uint8_t getOffset() const;
        uint8_t getFlags() const;
        uint16_t getWindows() const;
        uint16_t getChecksum() const;

        void setSrcPort(uint16_t srcPort);
        void setDstPort(uint16_t dstPort);
        void setSequence(uint32_t sequence);
        void setAck(uint32_t ack);
        void setOffset(uint8_t offset);
        void setFlags(uint8_t flags);
        void setWindows(uint16_t windows);
        void setChecksum(uint16_t checksum);

        std::string getName() const override;
        void print(std::ostream& os) const override;

        /// @brief Checks if the TCP frame contains the requested flag
        /// @param flag The precise flag to look for.
        /// @return A boolean, true if flag is found, false otherwise.
        bool hasFlag(uint8_t flag) const;
};