cmake_minimum_required(VERSION 3.10)

project(WebsocketParser)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fmt CONFIG REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)

add_executable(WebsocketParser main.cpp)

target_link_libraries(
    WebsocketParser
    PRIVATE
        fmt::fmt
        PcapPlusPlus::Pcap++
)
