## ========================== ## 
## == Project: SentinelDPI == ##
## == Author:  TheMatako   == ##
## ========================== ##

## CMakeLists.txt

cmake_minimum_required(VERSION 3.16)

project(sentinel-dpi LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)

add_executable(sentinel
    src/main.cpp
    # Protocols
    src/protocols/ProtocolLayer.cpp
    src/protocols/IPv4Layer.cpp
    src/protocols/TCPLayer.cpp
    src/protocols/EthernetLayer.cpp
    src/protocols/UDPLayer.cpp
    # Parser
    src/parser/PacketParser.cpp
    src/parser/PcapReader.cpp
    # DPI
    src/dpi/Alert.cpp
    src/dpi/RuleLoader.cpp
    # Core
    src/core/Packet.cpp
)