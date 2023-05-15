#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// if the condition is true, then the program prints the given message and exits
// returning error code
#define CHECK(cond, msg)  if(cond){ \
                              fprintf(stderr, "%s\n", msg); \
                              exit(1); \
                          }

#define OUTPUT_FILENAME "log.txt"

/* Network flow */
typedef struct network_flow{
	in_addr_t src_ip;
	u_short src_port;
	in_addr_t dest_ip;
	u_short dest_port;
	u_char proto;
} network_flow_t;

/* List of network flows */
typedef struct network_flow_list{
	network_flow_t network_flow;
	struct network_flow_list *next;
} network_flow_list_t;

/* Arguments and return values of packet_handler() function */
typedef struct packet_handler_args_retvals{
	/* Arguement */
	int port_filter;

	/* Return values */
	network_flow_list_t *network_flows;
	int total_network_flows_no;
	int tcp_network_flows_no;
	int udp_network_flows_no;
	int total_packets_no;
	int tcp_packets_no;
	int udp_packets_no;
	long tcp_bytes_no;
	long udp_bytes_no;
} packet_handler_args_retvals_t;

/*
 * For the ethernet and TCP headers, there was help from the following site from
 * the manual in assignment instructions: https://www.tcpdump.org/pcap.html
 */

/* Ethernet header: https://en.wikipedia.org/wiki/Ethernet_frame#Structure */
typedef struct ethernet_header{
	u_char mac_dest[ETHER_ADDR_LEN];  /* Destination host MAC address */
	u_char mac_src[ETHER_ADDR_LEN];   /* Source host MAC address */
	u_short ethertype; /* IP? ARP? RARP? etc */
} ethernet_header_t;
#define ETHER_HEADER_LEN (ETHER_ADDR_LEN + ETHER_ADDR_LEN + ETHER_TYPE_LEN)

/* IP header: https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header */
typedef struct ip_header{
	u_char ip_vhl;			/* version << 4 | header length >> 2 */  // header length counts the number of 32-bit words
	u_char ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
	u_char ip_ttl;			/* time to live */
	u_char ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src;	/* source address */
	struct in_addr ip_dest;	/* dest address */
} ip_header_t;

/* TCP header: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure */
typedef struct tcp_header{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int th_seq;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	u_char th_flags;
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
} tcp_header_t;

/* UDP header: https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure */
typedef struct udp_header{
    u_short src_port;  // source port
    u_short dest_port; // destination port
    u_short length;    // length
    u_short checksum;  // checksum
} udp_header_t;
#define UDP_HEADER_LEN 8  // UDP has 8 bytes header length

void usage();
void packet_sniffer(int live_bool_packets, char *pcap_input, int port_filter);
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int append_network_flow(network_flow_list_t **net_flows, network_flow_t new_net_flow);
void print_packet_info(ip_header_t ip_header, void *tcp_or_udp_header, u_char proto);


void *xmalloc(size_t size){
	void *ret_val = malloc(size);
	CHECK(ret_val == NULL, "Error allocating memory (malloc).");
	return ret_val;
}

int main(int argc, char **argv){

	int opt;
	int opt_checker = 0; // Used to check which options where used

	char *net_interface_name = NULL;
	char *packet_capture_input_filename = NULL;
	char *filter_expression = NULL;

	while( (opt = getopt(argc, argv, "i:r:f:h")) != -1){
		switch(opt){
			case 'i':
				net_interface_name = strdup(optarg);
				opt_checker |= 1;
				// TODO
				break;
			case 'r':
				packet_capture_input_filename = strdup(optarg);
				opt_checker |= 1<<1;
				break;
			case 'f':
				filter_expression = strdup(optarg);
				opt_checker |= 1<<2;
				break;
			case 'h':
			default:
				usage();
		}
	}

	char *pcap_input;
	int live_bool_packets;

	// Check that there is not a missing or an extra option
	if((opt_checker & 1) != 0){ // option i
		freopen(OUTPUT_FILENAME, "a+", stdout); // write output in the log file
		pcap_input = net_interface_name;
		live_bool_packets = 400; // let's sniff 400 packets
	}else if((opt_checker & (1<<1)) != 0){ // option r
		pcap_input = packet_capture_input_filename;
		live_bool_packets = -1;
	}else{
		usage();
	}

	int port_filter; // port filter
	if((opt_checker & (1<<2)) != 0){ // option f
		port_filter = atoi(filter_expression+5); // "port <number>" , "port " are 5 characters, skip them
	}else{
		port_filter = -1;
	}

	// start sniffing packets
	packet_sniffer(live_bool_packets, pcap_input, port_filter);

	return 0;
}

void usage(){
	printf("\n"
			"Usage:\n"
			"\t./pcap_ex\n\n"
			"Options:\n"
			"\t-i <network interface name>\n"
			"\t-r <packet capture filename>\n"
			"\t-f <filter expression>\n"
			"\t-h\n\n"
		  );

	exit(1);
}

/*
 * If the port_filter is -1 then no filter is applied.
 * If live_bool_packets == -1 or 0 then it captures offline, else it captures live live_bool_packets packets.
 */
void packet_sniffer(int live_bool_packets, char *pcap_input, int port_filter){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_stream;
	if(live_bool_packets > 0){
		pcap_stream = pcap_open_live(pcap_input, BUFSIZ, 1, 1000, errbuf);
	}else{
		pcap_stream = pcap_open_offline(pcap_input, errbuf);
	}

	CHECK(pcap_stream == NULL, errbuf);
	
	// load the arguments for packet handler() and call pcap_loop()
	packet_handler_args_retvals_t info = {0};
	info.port_filter = port_filter;
	int pcap_loop_retval = pcap_loop(pcap_stream, live_bool_packets, packet_handler, (u_char *)&info);

	if(pcap_loop_retval != 0){
		// check for any error
		CHECK(pcap_loop_retval == PCAP_ERROR_BREAK, "pcap_loop() returned PCAP_ERROR_BREAK.") else
		CHECK(pcap_loop_retval == PCAP_ERROR_NOT_ACTIVATED, "pcap_loop() returned PCAP_ERROR_NOT_ACTIVATED.") else
		CHECK(pcap_loop_retval == PCAP_ERROR, pcap_geterr(pcap_stream)) else
		{
			char errmsg[1000];
			sprintf(errmsg, "pcap_loop() returned unknown error code: %d.", pcap_loop_retval);
			CHECK(1, errmsg);
		}
	}

	printf("\n\n\n##############################################\n"
		   "Total number of network flows: %d\n"
		   "Number of TCP network flows: %d\n"
		   "Number of UDP network flows: %d\n"
		   "Total number of packets: %d\n"
		   "Number of TCP packets: %d\n"
		   "Number of UDP packets: %d\n"
		   "Number of TCP bytes: %ld\n"
		   "Number of UDP bytes: %ld\n"
		   "##############################################\n\n\n\n"
		   , info.total_network_flows_no, info.tcp_network_flows_no, info.udp_network_flows_no, info.total_packets_no, info.tcp_packets_no, info.udp_packets_no, info.tcp_bytes_no, info.udp_bytes_no);
	
	
}

void packet_handler(u_char *args_retval, const struct pcap_pkthdr *header, const u_char *packet){
	packet_handler_args_retvals_t *info = (packet_handler_args_retvals_t *)args_retval;

	int port_filter = info->port_filter;

	info->total_packets_no++; // general packet counter
	
	const ethernet_header_t *ethernet_header = (ethernet_header_t *)packet;

	const ip_header_t *ip_header;
	int ip_header_len;
	network_flow_t new_network_flow;
	int append_network_flow_retval;
	
	if(ntohs(ethernet_header->ethertype) == ETHERTYPE_IP){
		ip_header = (ip_header_t *)(packet + ETHER_HEADER_LEN);
		ip_header_len = (ip_header->ip_vhl & 0x0f) * 4; // conversion to bytes (ntohs not needed since ip_vhl is just one byte)
	}else if(ntohs(ethernet_header->ethertype) == ETHERTYPE_IPV6){
		return; // not done
	}else{
		return;
	}
	
	
	switch(ip_header->ip_p){ // find the protocol, no need for ntohs since it is just a byte
		case IPPROTO_TCP:
			;
			tcp_header_t *tcp_header = (tcp_header_t *)(packet + ETHER_HEADER_LEN + ip_header_len); // tcp header

			// Apply the port filter, if given
			if(port_filter != -1 && 
					!(port_filter == ntohs(tcp_header->th_sport) || port_filter == ntohs(tcp_header->th_dport))) // if filter is applied, it must match either source or destination port
				break;

			info->tcp_packets_no++; // tcp packet counter

			new_network_flow = (network_flow_t){ip_header->ip_src.s_addr, tcp_header->th_sport, ip_header->ip_dest.s_addr, tcp_header->th_dport, IPPROTO_TCP}; // create new network flow
			append_network_flow_retval = append_network_flow(&info->network_flows, new_network_flow); // append the new network flow if it does not already exist, and count it
			info->total_network_flows_no += append_network_flow_retval; // count it
			info->tcp_network_flows_no += append_network_flow_retval; // count it

			info->tcp_bytes_no += header->len; // tcp byte counter (for the whole packet, not just header)

			print_packet_info(*ip_header, tcp_header, IPPROTO_TCP);

			break;

		case IPPROTO_UDP:
			;
			udp_header_t *udp_header = (udp_header_t *)(packet + ETHER_HEADER_LEN + ip_header_len); // udp header

			// Apply the port filter, if given
			if(port_filter != -1 && 
					!(port_filter == ntohs(udp_header->src_port) || port_filter == ntohs(udp_header->dest_port))) // if filter is applied, it must match either source or destination port
				break;
			info->udp_packets_no++; // udp packet counter

			new_network_flow = (network_flow_t){ip_header->ip_src.s_addr, udp_header->src_port, ip_header->ip_dest.s_addr, udp_header->dest_port, IPPROTO_UDP}; // create new network flow
			append_network_flow_retval = append_network_flow(&info->network_flows, new_network_flow); // append the new network flow if it does not already exist
			info->total_network_flows_no += append_network_flow_retval; // count it
			info->udp_network_flows_no += append_network_flow_retval; // count it

			info->udp_bytes_no += header->len; // udp byte counter (for the whole packet, not just header)

			print_packet_info(*ip_header, udp_header, IPPROTO_TCP);
			break;
	}
}

/**
 * Append the given network flow to the given list if it does not already exists
 * in it, else don't append it. Return 1 if it was appended, else return 0.
 */
int append_network_flow(network_flow_list_t **net_flows, network_flow_t new_net_flow){

	if(*net_flows == NULL){ // the very first network flow
		*net_flows = xmalloc(sizeof(network_flow_list_t));
		(*net_flows)->network_flow = new_net_flow;
		(*net_flows)->next = NULL;
		return 1;
	}

	network_flow_list_t *net_flow_node = *net_flows;
	while(1){ // iterate the list's nodes
		if(net_flow_node->network_flow.src_ip    == new_net_flow.src_ip    && 
		   net_flow_node->network_flow.src_port  == new_net_flow.src_port  && 
		   net_flow_node->network_flow.dest_ip   == new_net_flow.dest_ip   && 
		   net_flow_node->network_flow.dest_port == new_net_flow.dest_port && 
		   net_flow_node->network_flow.proto     == new_net_flow.proto) // same network flow found
			return 0;

		if(net_flow_node->next == NULL){ // reached the end and did not found any same network flow
			// append the new network flow
			net_flow_node->next = xmalloc(sizeof(network_flow_list_t));
			net_flow_node = net_flow_node->next;
			net_flow_node->network_flow = new_net_flow;
			net_flow_node->next = NULL;
			return 1;
		}

		net_flow_node = net_flow_node->next;
	}
}

/*
 * For each packet, this functions prints the requested information.
 */
void print_packet_info(ip_header_t ip_header, void *tcp_or_udp_header, u_char proto){
	
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	u_short src_port;
	u_short dest_port;
	char *protocol;
	int tcp_udp_header_len;
	int tcp_udp_payload_len;

	// IP addresses
	inet_ntop(AF_INET, &ip_header.ip_src, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip_header.ip_dest, dest_ip, INET_ADDRSTRLEN);

	// IP header length
	int ip_header_len = (ip_header.ip_vhl & 0x0f) * 4; // conversion to bytes (ntohs not needed since ip_vhl is just one byte)

	// for each protocol, find the needed information
	switch(ip_header.ip_p){ // find the protocol, no need for ntohs since it is just a byte
		case IPPROTO_TCP:
			;
			tcp_header_t tcp_header = *(tcp_header_t *)tcp_or_udp_header;
			protocol = "TCP";
			src_port = ntohs(tcp_header.th_sport);
			dest_port = ntohs(tcp_header.th_sport);
			tcp_udp_header_len = ((tcp_header.th_offx2 & 0xF0) >> 4) * 4; // take the data offset which specifies the size of the TCP header in 32-bit words and convert it to bytes by multiplying with 4
			tcp_udp_payload_len = ntohs(ip_header.ip_len) - (ip_header_len + tcp_udp_header_len);

			break;
		case IPPROTO_UDP:
			;
			udp_header_t udp_header = *(udp_header_t *)tcp_or_udp_header;
			protocol = "UDP";
			src_port = ntohs(udp_header.src_port);
			dest_port = ntohs(udp_header.dest_port);
			tcp_udp_header_len = UDP_HEADER_LEN;
			tcp_udp_payload_len = ntohs(udp_header.length) - UDP_HEADER_LEN;
			break;
		default:
			return;
	}

	printf("Source IP: %s\n"
		   "Destination IP: %s\n"
		   "Source port: %d\n"
		   "Destination port: %d\n"
		   "Protocol: %s\n"
		   "Header length (bytes): %d\n"
		   "Payload length (bytes): %d\n"
		   "\n-----------------------------------------\n\n"
		   , src_ip, dest_ip, src_port, dest_port, protocol, tcp_udp_header_len, tcp_udp_payload_len);
}
