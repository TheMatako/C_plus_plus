// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/ProtocolLayer.hpp

#pragma once

#include <ostream>
#include <string>

/// @brief Abstract base class representing a single network protocol layer within a packet.
/// Provides a polymorphic interface so heterogeneous protocol headers can be stored and processed uniformly.
class ProtocolLayer {
    public:
        virtual ~ProtocolLayer() = default;

        virtual std::string getName() const = 0;
        virtual void print(std::ostream& os) const = 0;
};

std::ostream& operator<<(std::ostream& os, const ProtocolLayer& layer);