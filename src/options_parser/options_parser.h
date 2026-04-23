#pragma once
#include "config.h"
#include <CLI/CLI.hpp>

class OptionsParser
{
public:
    OptionsParser();
    auto parse_config(int argc, char **argv) -> int32_t;
    auto get_interface() const noexcept -> std::string;
    auto get_port() const noexcept -> std::string;
    auto get_packet_count() const noexcept -> int32_t;

private:
    static constexpr int32_t help_found_code{100};
    std::string interface_{config::DEFAULT_INTERFACE};
    std::string port_;
    int32_t packet_count_{config::DEFAULT_PORT_COUNT};

    CLI::App cli_app_;
};