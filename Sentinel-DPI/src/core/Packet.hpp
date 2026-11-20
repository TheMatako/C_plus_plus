// ========================== // 
// == Project: SentinelDPI == //
// == Author:  TheMatako   == //
// ========================== //

// src/core/Packet.hpp

#pragma once

#include "../protocols/ProtocolLayer.hpp"

#include <cstddef>
#include <vector>
#include <memory>
#include <ostream>
#include <cstdint>
#include <concepts>

/// @brief Represents a single captured network packet flowing from the parser to the DPI engine.
/// Encapsulate the ordered stack of decoded protocol layers, the raw payload, and the capture timestamp.
class Packet {
    private:
        std::vector<std::unique_ptr<ProtocolLayer>> layers_;
        std::vector<uint8_t> payload_;
        double timestamp_;
    public:
        explicit Packet(double timestamp = 0.0);
        void addLayer(std::unique_ptr<ProtocolLayer> layer);
        void setPayload(std::vector<uint8_t> payload);
        const std::vector<uint8_t>& getPayload() const;
        const std::vector<std::unique_ptr<ProtocolLayer>>& getLayers() const;
        std::size_t layerCount() const;
        double getTimestamp() const;


        /// @brief Retrieves the first protocol layer matching the requested type.
        /// @tparam T The concrete ProtocolLayer subclass to look for.
        /// @return A const pointer to the layer if found, or nullptr otherwise.
        template <std::derived_from<ProtocolLayer> T>
        const T* getLayer() const {
            for (const auto& layer : layers_) {
                const T* casted = dynamic_cast<const T*>(layer.get());
                if (casted != nullptr) {
                    return casted;
                }
            }
            return nullptr;
        }
};

std::ostream& operator<<(std::ostream& os, const Packet& packet);