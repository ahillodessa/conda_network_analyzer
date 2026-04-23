#include "analyzer.h"
#include <fmt/core.h>

namespace analyzer
{
NetworkAnalyzer::NetworkAnalyzer(const options_parser::Options& options)
    : options_(options)
{
}

auto NetworkAnalyzer::start_analyze() -> int32_t
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle =
        pcap_open_live(options_.interface_.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!handle)
    {
        fmt::print(stderr, "Error: {}\n", errbuf);
        return 1;
    }

    fmt::print("Starting capture...\n");
    pcap_loop(handle, options_.packet_count_,
              &NetworkAnalyzer::static_wrapper_callback,
              reinterpret_cast<u_char*>(this));
    pcap_close(handle);

    return 0;
}

void NetworkAnalyzer::process_packet(const struct ::pcap_pkthdr* h,
                                     const u_char* p)
{
    auto data = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(p), h->len);

    if (data.size() < sizeof(EthernetHeader))
        return;

    auto eth = reinterpret_cast<const EthernetHeader*>(data.data());

    if (ntohs(eth->type) == 0x0800)
    {
        auto ip_data = data.subspan(sizeof(EthernetHeader));
        if (ip_data.size() < sizeof(IPv4Header))
            return;

        auto ip = reinterpret_cast<const IPv4Header*>(ip_data.data());

        fmt::print("SRC: {}.{}.{}.{} | DST: {}.{}.{}.{} | PROTO: {}\n",
                   (ip->saddr & 0xFF), (ip->saddr >> 8 & 0xFF),
                   (ip->saddr >> 16 & 0xFF), (ip->saddr >> 24 & 0xFF),
                   (ip->daddr & 0xFF), (ip->daddr >> 8 & 0xFF),
                   (ip->daddr >> 16 & 0xFF), (ip->daddr >> 24 & 0xFF),
                   (int)ip->protocol);
    }
}

void NetworkAnalyzer::static_wrapper_callback(u_char* user,
                                              const struct ::pcap_pkthdr* h,
                                              const u_char* p)
{
    auto* self = reinterpret_cast<NetworkAnalyzer*>(user);
    if (self)
    {
        self->process_packet(h, p);
    }
}
} // namespace analyzer