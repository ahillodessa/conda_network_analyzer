#pragma once

#include "options_parser.h"
#include <concepts>
#include <cstddef>
#include <fmt/core.h>
#include <pcap.h>
#include <span>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace analyzer
{

#pragma pack(push, 1)

struct EthernetHeader
{
    uint8_t dhost[6];
    uint8_t shost[6];
    uint16_t type;
};

struct IPv4Header
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

#pragma pack(pop)

class NetworkAnalyzer
{
public:
    NetworkAnalyzer() = delete;
    NetworkAnalyzer(const NetworkAnalyzer&) = delete;
    NetworkAnalyzer(NetworkAnalyzer&&) = delete;
    explicit NetworkAnalyzer(const options_parser::Options& options);

    auto start_analyze() -> int32_t;

private:
    void process_packet(const struct ::pcap_pkthdr* h, const u_char* p);
    static void static_wrapper_callback(u_char* user,
                                        const struct ::pcap_pkthdr* h,
                                        const u_char* p);
    options_parser::Options options_;
};

} // namespace analyzer
