#include "options_parser.h"

namespace options_parser
{

OptionsParser::OptionsParser() : cli_app_("Conda Network Analyzer"), options_()
{
}

int32_t OptionsParser::parse_config(int argc, char** argv)
{
    cli_app_.add_option("-i,--interface", options_.interface_,
                        "Interface name (example: eth0, any)");
    cli_app_.add_option("-n,--count", options_.packet_count_,
                        "How many packet proceed");

    try
    {
        cli_app_.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        // If -h or --help found -> exit application
        auto code = cli_app_.exit(e);
        if (code == 0)
        {
            return config::HELP_FOUND_CODE;
        }
        return code;
    }

    return 0;
}

auto OptionsParser::get_options() const noexcept -> Options { return options_; }

} // namespace options_parser
