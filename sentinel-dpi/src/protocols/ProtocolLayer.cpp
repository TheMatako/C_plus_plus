// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/protocols/ProtocolLayer.cpp

#include "ProtocolLayer.hpp"

std::ostream& operator<<(std::ostream& os, const ProtocolLayer& layer) {
    layer.print(os);
    return os;
}
