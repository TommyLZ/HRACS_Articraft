cmake_minimum_required(VERSION 3.10)
project(APAKE_Communication_CS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(apake_comm_server server.cpp)
add_executable(apake_comm_client client.cpp)
add_executable(apake_pcap_analyzer pcap_analyzer.cpp)
