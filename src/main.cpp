#include "analyzer/analyzer.h"
#include "options_parser/config.h"
#include "options_parser/options_parser.h"

int main(int argc, char** argv)
{
    options_parser::OptionsParser options_parser;
    auto parse_result = options_parser.parse_config(argc, argv);
    if (parse_result > 0)
    {
        return (parse_result == config::HELP_FOUND_CODE) ? 0 : parse_result;
    }

    analyzer::NetworkAnalyzer network_analyzer(options_parser.get_options());
    auto net_analyze_res = network_analyzer.start_analyze();

    return net_analyze_res;
}
