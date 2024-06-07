#include <pcap.h>
#include <iostream>
#include <string>
#include <cstring>
#include <netinet/if_ether.h>
#include <sstream>

#define ETHER_SNAPLEN 65535

// Helper function to convert hex character to integer
int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

// Helper function to parse MAC address string into byte array
bool parse_mac_address(const std::string &mac_str, u_char *mac) {
    if (mac_str.length() != 17 || mac == nullptr) {
        return false; // Invalid MAC address length
    }

    std::memset(mac, 0, ETHER_ADDR_LEN);

    for (size_t i = 0; i < 17; i += 3) {
        if (mac_str[i] == ':') continue; // Continue if delimiter

        int highPart = hexCharToInt(mac_str[i]);
        int lowPart = hexCharToInt(mac_str[i + 1]);
        
        if (highPart == -1 || lowPart == -1) {
            return false; // Invalid hex character
        }

        mac[i / 3] = (highPart << 4) | lowPart; // Combine high and low parts
    }
    return true;
}

// Function to convert NFLOG packets to Ethernet packets
bool nflog_to_eth(const std::string &infile, const std::string &outfile,
                  const std::string &src_mac, const std::string &dst_mac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int total_packets = 0, nflog_packets = 0, unchanged_packets = 0;

    // Open the input pcap file
    pcap_t *pcap = pcap_open_offline(infile.c_str(), errbuf);
    if (pcap == nullptr)
    {
        std::cerr << "Error opening input file: " << errbuf << std::endl;
        return false;
    }

    // Open the output pcap file
    pcap_t *out_pcap = pcap_open_dead(DLT_EN10MB, ETHER_SNAPLEN); // Creata a Ethernet pcap file
    pcap_dumper_t *dumper = pcap_dump_open(out_pcap, outfile.c_str());
    if (dumper == nullptr)
    {
        std::cerr << "Error opening output file: " << pcap_geterr(pcap) << std::endl;
        return false;
    }

    u_char src_mac_bytes[ETHER_ADDR_LEN];
    u_char dst_mac_bytes[ETHER_ADDR_LEN];
    if (!parse_mac_address(src_mac, src_mac_bytes) || !parse_mac_address(dst_mac, dst_mac_bytes))
    {
        std::cerr << "Invalid MAC address." << std::endl;
        return false;
    }

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while (pcap_next_ex(pcap, &header, &pkt_data) == 1)
    {
        total_packets++; // Increment total packets counter

        // Check if packet is an NFLOG packet
        if (pcap_datalink(pcap) == DLT_NFLOG)
        {
            nflog_packets++; // Increment NFLOG packets counter

            struct ether_header eth_hdr;
            __uint16_t nflog_family = pkt_data[0]; // NFLOG family
            
            memcpy(eth_hdr.ether_shost, src_mac_bytes, ETHER_ADDR_LEN);
            memcpy(eth_hdr.ether_dhost, dst_mac_bytes, ETHER_ADDR_LEN);
            if (nflog_family == AF_INET)
            {
                eth_hdr.ether_type = htons(ETHERTYPE_IP);
            }
            else if (nflog_family == AF_INET6)
            {
                eth_hdr.ether_type = htons(ETHERTYPE_IPV6);
            }
            else
            {
                // TODO: Handle other NFLOG families
                std::cout << "Unknown NFLOG family (idx: " << total_packets << "): " << nflog_family << std::endl;
                eth_hdr.ether_type = htons(nflog_family);
            }
            
            // Remove NFLOG header
            int nflog_header_len = 4; // Fixed NFLOG header length: Family, Version, Resource ID
            while (true)
            {
                // Parse TLV header
                int tlv_type = (pkt_data[nflog_header_len + 3] << 8) + pkt_data[nflog_header_len + 2];
                int tlv_len = (pkt_data[nflog_header_len + 1] << 8) + pkt_data[nflog_header_len];
                // If TLV length is not a multiple of 4, round up to the nearest multiple of 4
                if (tlv_len % 4 != 0)
                {
                    tlv_len += 4 - tlv_len % 4;
                }
                // Check if TLV type is NFULA_PAYLOAD
                if (tlv_type == 0x0009)
                {
                    nflog_header_len += 4;
                    break;
                }
                nflog_header_len += tlv_len;
            }

            u_char new_packet[ETHER_SNAPLEN];
            memcpy(new_packet, &eth_hdr, sizeof(eth_hdr)); // Add Ethernet header
            memcpy(new_packet + sizeof(eth_hdr), pkt_data + nflog_header_len, header->caplen - nflog_header_len); // Add original packet

            struct pcap_pkthdr new_header = *header;
            // Skip NFLOG header
            new_header.caplen -= nflog_header_len;
            new_header.len -= nflog_header_len;

            new_header.caplen += sizeof(eth_hdr);
            new_header.len += sizeof(eth_hdr);

            pcap_dump(reinterpret_cast<u_char *>(dumper), &new_header, new_packet);
        }
        else
        {
            unchanged_packets++; // Increment unchanged packets counter
            pcap_dump(reinterpret_cast<u_char *>(dumper), header, pkt_data);
            std::cout << "Unchanged packet (idx: " << total_packets << ")" << std::endl;
        }
    }

    // Cleanup
    pcap_close(pcap);
    pcap_close(out_pcap);
    pcap_dump_close(dumper);

    std::cout << "Transfer '" << infile << "' to '" << outfile << "' successfully. (Total packets: " << total_packets << "; " << "NFLOG packets: " << nflog_packets << "; " << "Unchanged packets: " << unchanged_packets << ")" << std::endl;

    return true;
}

int main(int argc, char *argv[])
{
    std::string infile, outfile, src_mac, dst_mac;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
        {
            infile = argv[++i];
        }
        else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc)
        {
            outfile = argv[++i];
        }
        else if (strcmp(argv[i], "-src_mac") == 0 && i + 1 < argc)
        {
            src_mac = argv[++i];
        }
        else if (strcmp(argv[i], "-dst_mac") == 0 && i + 1 < argc)
        {
            dst_mac = argv[++i];
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            std::cout << "Usage: " << argv[0] << " -r <input_file> [-w <output_file>] [-src_mac <src_mac>] [-dst_mac <dst_mac>]" << std::endl;
            return 0;
        }
        else {
            std::cerr << "Unknown option: " << argv[i] << std::endl;
            return 1;
        }
    }

    if (infile.empty())
    {
        std::cerr << "Input file is required ('-r')." << std::endl;
        return 1;
    }

    if (outfile.empty())
    {
        size_t pos = infile.find_last_of('.');
        outfile = infile.substr(0, pos) + "-eth" + infile.substr(pos);
    }

    if (src_mac.empty())
    {
        src_mac = "11:11:11:11:11:11";
    }

    if (dst_mac.empty())
    {
        dst_mac = "22:22:22:22:22:22";
    }

    if (!nflog_to_eth(infile, outfile, src_mac, dst_mac))
    {
        std::cerr << "Failed to process pcap file '" << infile << "'." << std::endl;
        return 1;
    }

    return 0;
}