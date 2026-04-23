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
    auto packet = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(p), h->len);
    if (packet.size() < sizeof(ether_header))
        return;

    auto eth = reinterpret_cast<const ether_header*>(packet.data());

    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        auto ip_data = packet.subspan(sizeof(ether_header));
        if (ip_data.size() < sizeof(iphdr))
            return;

        auto ip = reinterpret_cast<const iphdr*>(ip_data.data());
        fmt::print("SRC: {} | DST: {} | PROTO: {}\n",
                   inet_ntoa(*(struct in_addr*)&ip->saddr),
                   inet_ntoa(*(struct in_addr*)&ip->daddr), (int)ip->protocol);
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