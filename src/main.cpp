#include "analyzer/analyzer.h"
#include "options_parser/options_parser.h"
#include <fmt/core.h>
#include <pcap.h>

void packet_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    auto data = std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(p), h->len);
    Analyzer::process_packet(data);
}

int main(int argc, char **argv)
{
    OptionsParser options_parser;
    auto result = options_parser.parse_config(argc, argv);
    if (result > 0)
    {
        return result;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(options_parser.get_interface().c_str(),
                                    BUFSIZ, 1, 1000, errbuf);

    if (!handle)
    {
        fmt::print(stderr, "Error: {}\n", errbuf);
        return 1;
    }

    fmt::print("Starting capture...\n");
    pcap_loop(handle, options_parser.get_packet_count(), packet_callback,
              nullptr);
    pcap_close(handle);
    return 0;
}
