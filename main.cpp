#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

struct EthernetHeader {
    u_char ether_dst[6];
    u_char ether_src[6];
    uint16_t type;
};

struct IpHeader {
    uint8_t version_ihl;
    uint8_t service_type;
    uint16_t totalLen;
    uint16_t identification;
    uint16_t flag;
    uint8_t time2live;
    uint8_t protocol;

    uint16_t checksum;
    u_char ip_src[4];
    u_char ip_dst[4];
};

struct TCPHeader {
    uint16_t port_src;
    uint16_t port_dst;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent;
};



void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

uint16_t my_ntohs(uint16_t n) {	// network byte order to host byte order (2byte)
    return n << 8 | n >> 8;
}

uint32_t my_ntohl(uint32_t n) { //
    return
        ((n & 0x000000FF) << 24) |
        ((n & 0x0000FF00) << 8) |
        ((n & 0x00FF0000) >> 8) |
        ((n & 0xFF000000) >> 24);
}

void print_mac(const u_char* mac);
void print_ip(const u_char* ip);
//void print_port(const u_char* port);
void print_port(uint16_t port);

uint16_t parsing_ethernet_header(const u_char* data)
{
    printf("=========== Ethernet header ===========\n");
    const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(data);

    printf("Dmac : ");
    print_mac(ether_header->ether_dst);
    printf("Smac : ");
    print_mac(ether_header->ether_src);

    return my_ntohs(ether_header->type);
}

uint16_t parsing_ip_header(const u_char* data)
{
    printf("============== Ip header ==============\n");
    const IpHeader* ip_header = reinterpret_cast<const IpHeader*>(data);

    printf("Sip : ");
    print_ip(ip_header->ip_src);
    printf("Dip : ");
    print_ip(ip_header->ip_dst);

    return ip_header->protocol;
}

uint8_t parsing_tcp_header(const u_char* data)
{
    printf("============= TCP header ==============\n");
    const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(data);

    printf("Sport : ");
    print_port(tcp_header->port_src);
    printf("Dport : ");
    print_port(tcp_header->port_dst);

    uint8_t headerLen = (tcp_header->flags & 0xFF)>>2;
    return headerLen;
}


void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X:\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
    printf("%u\n", (port&0xFF) << 8 | port >> 8);
}

int main(int argc, char* argv[]) {
  char track[] = "취약점"; // "개발", "컨설팅", "포렌식"
  char name[] = "권재승";
  printf("[bob8][%s]pcap_test[%s]\n\n", track, name);

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);    // linux pcap_open
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    const u_char* packet_end = packet+header->caplen;

    // type 0x0800 is IP
    if(parsing_ethernet_header(packet) == 0x0800){
        packet += sizeof(EthernetHeader);   // packet pointer move, EthernetHeader is 14 byte
        // protocol 6 is TCP
        if(parsing_ip_header(packet) == 6){
            packet += sizeof(IpHeader); // packet pointer move, IpHeader is 20 byte
            uint8_t h_len = parsing_tcp_header(packet);
            packet += h_len;// packet pointer move, TCPHeader size plus

            if(packet<packet_end){
                printf("================ Data =================\n");
                for(int i=0; packet<packet_end && i<10; i++){
                    printf("%02X ", *(packet++));
                }
                printf("\n");
            }
        }
    }
    printf("=======================================\n\n");
  }

  pcap_close(handle);
  return 0;
}



