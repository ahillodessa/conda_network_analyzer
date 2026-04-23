cmake_minimum_required(VERSION 3.15)
project(network-analyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fmt REQUIRED)
find_package(CLI11 REQUIRED)

find_library(PCAP_LIB pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)

add_executable(${PROJECT_NAME}
    src/analyzer/analyzer.cpp
    src/options_parser/options_parser.cpp
    src/main.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    src/analyzer
    src/options_parser
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    fmt::fmt
    ${PCAP_LIB}
    CLI11::CLI11
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
