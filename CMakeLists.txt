cmake_minimum_required(VERSION 3.10)

project(WebsocketParser)

find_package(fmt CONFIG REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)

add_executable(WebsocketParser main.cpp)

target_link_libraries(
    WebsocketParser
    PRIVATE
        fmt::fmt
        PcapPlusPlus::Pcap++
)
