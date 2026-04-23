#include "options_parser.h"

OptionsParser::OptionsParser() : cli_app_("Conda Network Analyzer") {}

int32_t OptionsParser::parse_config(int argc, char **argv)
{
    cli_app_.add_option("-i,--interface", interface_,
                        "Interface name (example: eth0, any)");
    cli_app_.add_option("-n,--count", packet_count_, "How many packet proceed");

    try
    {
        cli_app_.parse(argc, argv);
    }
    catch (const CLI::ParseError &e)
    {
        // If -h or --help found -> exit application
        auto code = cli_app_.exit(e);
        if (code == 0)
        {
            return help_found_code;
        }
        return code;
    }

    return 0;
}

auto OptionsParser::get_interface() const noexcept -> std::string
{
    return interface_;
}

auto OptionsParser::get_port() const noexcept -> std::string { return port_; }

auto OptionsParser::get_packet_count() const noexcept -> int32_t
{
    return packet_count_;
}