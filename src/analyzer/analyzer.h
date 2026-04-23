#pragma once
#include <arpa/inet.h>
#include <cstddef>
#include <fmt/core.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <span>

template <typename T>
concept NetworkHeader = std::is_standard_layout_v<T>;

class Analyzer
{
public:
    static void process_packet(std::span<const std::byte> packet)
    {
        if (packet.size() < sizeof(ether_header))
            return;

        auto eth = reinterpret_cast<const ether_header *>(packet.data());

        if (ntohs(eth->ether_type) == ETHERTYPE_IP)
        {
            auto ip_data = packet.subspan(sizeof(ether_header));
            if (ip_data.size() < sizeof(iphdr))
                return;

            auto ip = reinterpret_cast<const iphdr *>(ip_data.data());
            fmt::print("SRC: {} | DST: {} | PROTO: {}\n",
                       inet_ntoa(*(struct in_addr *)&ip->saddr),
                       inet_ntoa(*(struct in_addr *)&ip->daddr),
                       (int)ip->protocol);
        }
    }
};
