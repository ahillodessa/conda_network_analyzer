#pragma once
#include "config.h"
#include <CLI/CLI.hpp>

namespace options_parser
{

struct Options
{
    std::string interface_{config::DEFAULT_INTERFACE};
    std::string port_;
    int32_t packet_count_{config::DEFAULT_PORT_COUNT};
};

class OptionsParser
{
public:
    OptionsParser();
    auto parse_config(int argc, char** argv) -> int32_t;
    auto get_options() const noexcept -> Options;

private:
    CLI::App cli_app_;
    Options options_;
};

} // namespace options_parser
