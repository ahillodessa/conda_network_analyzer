#pragma once
#include "options_parser.h"
#include <arpa/inet.h>
#include <concepts>
#include <cstddef>
#include <fmt/core.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <span>

namespace analyzer
{

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
