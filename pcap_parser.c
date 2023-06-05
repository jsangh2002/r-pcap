/*
** Copyright (c) 2023 Jasmine Sanghvi
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>  /* for ntohl/htonl etc */
#include <assert.h>

#define COMPILE_AS_R_LIB 1

#if COMPILE_AS_R_LIB
#include <R.h>
#include <Rinternals.h>
#include <Rmath.h>
#endif


#define MAX_HASH_LENGTH  131072 
#define MAX_NUM_PACKETS  1000000
#define MAX_PACKET_SIZE  2000


struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int thiszone;            /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in bytes */
	uint32_t network;        /* data link type */
};


struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
};


typedef uint8_t mac_addr_t[6]; 

struct ethernet_hdr_s {
	mac_addr_t dst_mac; 
	mac_addr_t src_mac;
	uint16_t type_length;       /* NETWORK ORDER */ 
};


struct ipv4_hdr_s {
	uint8_t vers_hlen;
	uint8_t dscp_ecn;
	uint16_t total_len;         /* NETWORK ORDER */
	uint16_t identification;    /* NETWORK ORDER */
	uint16_t flags_frag_ofs;    /* NETWORK ORDER */
	uint8_t ttl;
	uint8_t proto; 
	uint16_t hdr_checksum;      /* NETWORK ORDER */
	uint32_t src_ip;            /* NETWORK ORDER */
	uint32_t dst_ip;            /* NETWORK ORDER */
};


struct tcp_hdr_s {
	uint16_t src_port;         /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint32_t seq_num;          /* NETWORK ORDER */
	uint32_t ack_num;          /* NETWORK ORDER */
	uint16_t ofs_ctrl;         /* NETWORK ORDER */        
	uint16_t window_size;      /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
	uint16_t urgent_pointer;   /* NETWORK ORDER */
};


struct udp_hdr_s {
	uint16_t src_port;         /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint16_t total_len;        /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
};


struct icmp_hdr_s {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;         /* NETWORK ORDER */
};


struct counters {
	uint32_t num_tcp_flows; 
	uint32_t non_eth;
	uint32_t num_ipv4_pkts;
	uint32_t num_icmp_pkts;
	uint32_t num_udp_pkts;
	uint32_t num_tcp_pkts;
	uint32_t num_not_tcp_udp_icmp_pkts;
	uint32_t num_ipv6_pkts; 
	uint32_t num_arp_pkts; 
};


/*
** flow
*/
typedef enum {
	TCP_FLOW,
	UDP_FLOW,
	ICMP_FLOW,
	unknown
} l4_flow_type_t;


struct flow_s {
	uint32_t flow_id;
	uint32_t init_ip; 
	uint32_t resp_ip; 
	uint16_t init_port; 
	uint16_t resp_port; 
	l4_flow_type_t l4_flow_type;
	uint16_t vlan;
	uint8_t init_wscale;
	uint8_t resp_wscale;

	uint8_t is_open;
	uint8_t is_closed; 

	uint32_t num_pkts;
	uint32_t init_num_bytes; /* from initiator */
	uint32_t init_num_pkts;
	uint32_t resp_num_bytes; /* from responder */
	uint32_t resp_num_pkts;

	uint64_t start_time; /* first syn */
	uint64_t end_time;   /* fin_ack or ack */

	uint64_t init_timestamps [MAX_NUM_PACKETS]; /* timestamps on pkts from initiator */
	uint64_t resp_timestamps [MAX_NUM_PACKETS]; /* timestamps on pkts from responder */
	uint32_t init_seq_nums [MAX_NUM_PACKETS];
	uint32_t init_ack_nums [MAX_NUM_PACKETS];
	uint32_t resp_seq_nums [MAX_NUM_PACKETS];
	uint32_t resp_ack_nums [MAX_NUM_PACKETS];
	uint32_t init_window_sizes [MAX_NUM_PACKETS];
	uint32_t resp_window_sizes [MAX_NUM_PACKETS];
	uint32_t packet_idx [MAX_NUM_PACKETS];      /* index to pkt contents in global state */

	struct flow_s *next;
};


struct ipv4_info_s {
	uint32_t ip_addr;
	uint32_t num_pkts_sent;
	uint32_t num_pkts_rcvd;
	uint32_t num_bytes_sent;
	uint32_t num_bytes_rcvd;
	uint32_t num_frags_sent;
	uint32_t num_frags_rcvd;
	struct ipv4_info_s *next;
};


/*
** global state 
*/
static uint8_t g_packets [MAX_NUM_PACKETS][MAX_PACKET_SIZE];
static struct flow_s *g_flow_table [MAX_HASH_LENGTH]; 
static struct ipv4_info_s *g_ipv4_list; 
static uint32_t g_num_list_elements;
static uint8_t g_dummy_buf [16000];
static struct counters g_stats;
static uint32_t g_flow_id = 0;
static int g_debug_flag = 0;
static int first_time = 1;


static void 
init_state (void)
{
	int i;
	struct flow_s *t, *s; 
	struct ipv4_info_s *t1, *s1;

	g_flow_id = 0;
	memset (&g_stats, 0, sizeof(g_stats));

	if (first_time) {
		memset (g_flow_table, 0, sizeof (g_flow_table));
		first_time = 0;
	}
	else {
		for (i = 0; i < MAX_HASH_LENGTH; i++) {
			t = g_flow_table[i];
			while (t) {
				s = t->next;
				free (t);
				t = s; 
			}
			g_flow_table[i] = NULL;
		}
			
		t1 = g_ipv4_list;	
		while (t1) {
			s1 = t1->next;
			free (t1);			
			t1 = s1; 
		}
	}

	g_ipv4_list = NULL;
	g_num_list_elements = 0;
}


struct ipv4_info_s *
find_ipv4_info (uint32_t ip)
{
	struct ipv4_info_s *tmp = g_ipv4_list;
	while (tmp != NULL) {
		if (ip == tmp->ip_addr) {
			return tmp;
		}
		tmp = tmp->next;
	} 
	return NULL;
}


static void 
add_to_ipv4_list (struct ipv4_info_s *f)
{
	f->next = g_ipv4_list;
	g_ipv4_list = f;
	g_num_list_elements++;
}


static void print_global_hdr (struct pcap_hdr_s *p_hdr)
{
	printf ("magic number = %x\n", p_hdr->magic_number);
	printf ("version_major = %u\n", p_hdr->version_major);
	printf ("version_minor = %u\n", p_hdr->version_minor);	
	printf ("thiszone = %d\n", p_hdr->thiszone);	
	printf ("sigfigs = %u\n", p_hdr->sigfigs);	
	printf ("snaplen = %u\n", p_hdr->snaplen);	
	printf ("network = %u\n", p_hdr->network);	
}

static void print_counters (struct counters *c)
{
	printf("number non ethernet = %u\n",c->non_eth);
	printf("number of ipv4 packets = %u\n",c->num_ipv4_pkts);
	printf("num ipv6 packets = %u\n",c->num_ipv6_pkts);
	printf("num arp packets = %u\n", c->num_arp_pkts);
	printf("number icmp packets = %u\n",c->num_icmp_pkts);
	printf("number udp packets = %u\n",c->num_udp_pkts);
	printf("number tcp packets = %u\n",c->num_tcp_pkts);
	printf("number non tcp udp or icmp packets %u\n",c->num_not_tcp_udp_icmp_pkts);
}


static void inline 
ip_to_str (char *str, int str_sz, uint32_t ip)
{       
	snprintf (str, str_sz, "%u.%u.%u.%u",
        	(ip & 0xff000000) >> 24,
        	(ip & 0x00ff0000) >> 16,
        	(ip & 0x0000ff00) >> 8,
        	(ip & 0x000000ff));
}


static void
record_tcp_pkt (struct flow_s *flow, int pktnum, uint64_t tstamp, int from_initiator, struct tcp_hdr_s *tcp_hdr, int data_len)
{
	if (!from_initiator) {
		/* 
		** packet is from responder 
		*/

		flow->resp_window_sizes [flow->resp_num_pkts] = ntohs(tcp_hdr->window_size) << flow->resp_wscale;
		flow->resp_timestamps[flow->resp_num_pkts] = tstamp;
		flow->resp_seq_nums [flow->resp_num_pkts] = tcp_hdr->seq_num; 
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->resp_ack_nums[flow->resp_num_pkts] = tcp_hdr->ack_num; 
		}
		flow->resp_num_pkts++;
		flow->resp_num_bytes += data_len;
	}
	else {
		/* 
		** packet is from initiator 
		*/

		flow->init_window_sizes [flow->init_num_pkts] = ntohs(tcp_hdr->window_size) << flow->init_wscale;
		flow->init_timestamps[flow->init_num_pkts] = tstamp;
		flow->init_seq_nums[flow->init_num_pkts] = tcp_hdr->seq_num; 
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->init_ack_nums[flow->init_num_pkts] = tcp_hdr->ack_num;
		}
		flow->init_num_pkts++;
		flow->init_num_bytes += data_len;
	}
	flow->packet_idx [flow->num_pkts] = pktnum;
	flow->num_pkts++;
}


static void 
add_to_hash_table (struct flow_s *flow)
{
	uint32_t hash;

	flow->flow_id = g_flow_id;
	g_flow_id++;

	hash = (flow->init_ip ^ flow->resp_ip ^ flow->init_port ^ flow->resp_port) % MAX_HASH_LENGTH; 
	flow->next = g_flow_table[hash];
	g_flow_table[hash] = flow;
}


static struct flow_s *
find_flow_v4 (uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
{
	uint32_t hash;
	struct flow_s *f;

	hash = (sip ^ dip ^ sport ^ dport) % MAX_HASH_LENGTH; 
	f = g_flow_table [hash];
	while (f) {
		if ((f->init_ip == sip && f->init_port == sport && f->resp_ip == dip && f->resp_port == dport) ||
			(f->resp_ip == sip && f->resp_port == sport && f->init_ip == dip && f->init_port == dport)) {
			return f;
		}
		f = f->next;
	}
	return NULL;
}


/* 
** return 1 to continue parsing l4  or 0 on stop further parsing 
*/
static int
parse_ipv4 (int pkt_num, int offset, int *next_offset, struct ipv4_hdr_s *ip_hdr)
{
	int is_frag = 0;
	int hdr_len, data_len;
	struct ipv4_info_s *ip_info;
	uint8_t *packet = g_packets[pkt_num];
	
	memcpy (ip_hdr, &packet[offset], sizeof (struct ipv4_hdr_s));

	ip_hdr->flags_frag_ofs = ntohs(ip_hdr->flags_frag_ofs);    
	if (ip_hdr->flags_frag_ofs & 0x1fff) {
		is_frag = 1;
	}

	ip_hdr->src_ip = ntohl (ip_hdr->src_ip); 
	ip_hdr->dst_ip = ntohl (ip_hdr->dst_ip); 
	ip_hdr->total_len = ntohs (ip_hdr->total_len); 

	hdr_len = (ip_hdr->vers_hlen & 0xf) * 4;
	data_len = ip_hdr->total_len - hdr_len;

	ip_info = find_ipv4_info (ip_hdr->src_ip); 
	if (ip_info == NULL) {
		ip_info = malloc (sizeof (struct ipv4_info_s));
		assert (ip_info);

		ip_info->ip_addr = ip_hdr->src_ip;
		ip_info->num_pkts_sent = 1;
		ip_info->num_bytes_sent = data_len;
		ip_info->num_pkts_rcvd = 0;
		ip_info->num_bytes_rcvd =  0;
		ip_info->num_frags_sent = (is_frag) ? 1 : 0;
		add_to_ipv4_list (ip_info);
	}
	else {
		ip_info->num_pkts_sent++;
		ip_info->num_bytes_sent += data_len;
		if (is_frag)
			ip_info->num_frags_sent++;
	}

	ip_info = find_ipv4_info (ip_hdr->dst_ip);
	if (ip_info == NULL) {
		ip_info = malloc (sizeof(struct ipv4_info_s));
		assert (ip_info);

		ip_info->ip_addr = ip_hdr->dst_ip;
		ip_info->num_pkts_sent = 0;
		ip_info->num_bytes_sent = 0;
		ip_info->num_pkts_rcvd = 1;
		ip_info->num_bytes_rcvd = data_len;
		ip_info->num_frags_rcvd = (is_frag) ? 1 : 0;
		add_to_ipv4_list (ip_info); 
	}
	else {
		ip_info->num_pkts_rcvd++; 
		ip_info->num_bytes_rcvd += data_len; 
		if (is_frag)
			ip_info->num_frags_rcvd++;
	}

	*next_offset = offset + hdr_len; 
	return ((is_frag) ? 0 : 1);
}


static int
parse_tcp (int pkt_num, int offset, int *next_offset, struct ipv4_hdr_s *ip_hdr, uint64_t tstamp)
{
	int data_len;
	int wscale = 0, tcp_hlen;
	struct tcp_hdr_s tcp_hdr; 
	uint8_t *packet = g_packets [pkt_num];

	memcpy (&tcp_hdr, packet + offset, sizeof(struct tcp_hdr_s));
							
	tcp_hdr.ofs_ctrl = ntohs (tcp_hdr.ofs_ctrl);
	tcp_hdr.seq_num  = ntohl (tcp_hdr.seq_num); 
	tcp_hdr.ack_num  = ntohl (tcp_hdr.ack_num); 
	tcp_hdr.src_port = ntohs (tcp_hdr.src_port); 
	tcp_hdr.dst_port = ntohs (tcp_hdr.dst_port); 

	tcp_hlen = ((tcp_hdr.ofs_ctrl & 0xf000) >> 12) * 4;
	data_len = ip_hdr->total_len - ((ip_hdr->vers_hlen & 0xf) * 4) - tcp_hlen;

	if (tcp_hlen > 20) {
		/* 
		** parse TCP options to find Window Scaling factor
		*/
		int cur = 20;
		int rem = tcp_hlen - 20;  /* 20 is length without options */

		while (rem > 0) {
			uint8_t kind = packet[offset + cur];

			/* no-op */
			if (kind == 1) {
				rem = rem - 1;
				cur = cur + 1;
				continue;
			}

			if (kind == 0) {
				break;
			}

			uint8_t len = packet[offset + cur + 1];
			if (kind != 3) {
				cur = cur + len;
				rem = rem - len;
			}
			else {
				/* window scaling option */
				/* this will be present only in syn/syn_ack */
				wscale = packet[offset + cur + 2];
				break;
			}
		}
	}
 
	struct flow_s *f = find_flow_v4 (ip_hdr->src_ip, tcp_hdr.src_port, ip_hdr->dst_ip, tcp_hdr.dst_port); 

	/* SYN */
	if ((tcp_hdr.ofs_ctrl & 0x12) == 0x02) {
		if (f == NULL || f->is_closed == 1) {
			/* if f == NULL assume that this is first syn pkt */
			f = malloc (sizeof (struct flow_s));
			assert (f);

			memset (f, 0, sizeof (struct flow_s));

			f->init_ip = ip_hdr->src_ip;
			f->resp_ip = ip_hdr->dst_ip;
			f->init_port = tcp_hdr.src_port;
			f->resp_port = tcp_hdr.dst_port;
			f->is_open = 1;
			f->init_wscale = wscale;
			f->l4_flow_type = TCP_FLOW;
			record_tcp_pkt (f, pkt_num, tstamp, 1, &tcp_hdr, data_len);

			add_to_hash_table (f); 	
			g_stats.num_tcp_flows++; 
		}
	}
	else if (f) {
		int is_init = (ip_hdr->src_ip == f->init_ip && tcp_hdr.src_port == f->init_port) ? 1 : 0;
		if (!is_init && !f->resp_wscale && wscale) {
			f->resp_wscale = wscale;
		}

		record_tcp_pkt (f, pkt_num, tstamp, is_init, &tcp_hdr, data_len);
		if (tcp_hdr.ofs_ctrl & 0x1 == 0x1 || tcp_hdr.ofs_ctrl & 0x4 == 0x4) {
			f->is_open = 0;
			f->is_closed = 1;
		}
	}
}


static int 
parse_pcap_file (const char *file_name)
{
	FILE *fp;
	struct flow_s *f;
	uint16_t ether_type;
	int n, rc, len, ofs, cont;
	struct pcap_hdr_s global_hdr;
	struct pcaprec_hdr_s rec_hdr;
	struct ethernet_hdr_s *eth_hdr;
	struct ipv4_hdr_s ip_hdr;

	fp = fopen (file_name, "r");
	if (!fp) {
		printf ("error reading file %s\n", file_name);
		return -1;
	}

	printf ("reading pcap file %s ...\n", file_name);

	rc = fread (&global_hdr, sizeof(struct pcap_hdr_s), 1, fp);	
	if (rc != 1) {
		printf ("error reading pcap global hdr\n");
		return -2;
	}

	n = 0;
	while (n < MAX_NUM_PACKETS) {
		/*
		** read pcap pkt hdr
		*/
		rc = fread (&rec_hdr, sizeof(struct pcaprec_hdr_s), 1, fp);
		if (rc != 1) {
			if (!feof (fp)) {
				printf ("file read error!\n"); 
			}
			break;
		}

		uint64_t tstamp = ((uint64_t)(rec_hdr.ts_sec) * 1000000LL) + (uint64_t) rec_hdr.ts_usec;

		/*
		** read packet
		*/
		len = (rec_hdr.incl_len > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : rec_hdr.incl_len;
		rc = fread (g_packets[n], 1, len, fp);
		if (rc != len) {
			if (!feof (fp)) {
				printf ("file read error\n");
			}
			break;
		}


		if ((rec_hdr.incl_len - len) > 0) {
			rc = fread (g_dummy_buf, 1, rec_hdr.incl_len-len, fp);
		}
		
		/*
		** parse packet hdrs ...
		*/

		eth_hdr = (struct ethernet_hdr_s *) g_packets[n];
		eth_hdr->type_length = ntohs(eth_hdr->type_length); 

		if (eth_hdr->type_length <= 1500) {
			/* skip snap/802.3 */
			continue;
		}

		/* vlan tpid */
		if (eth_hdr->type_length == 0x8100) {
			memcpy (&ether_type, g_packets[n]+16, 2);
			ether_type = ntohs(ether_type);
			ofs = sizeof(struct ethernet_hdr_s) + 4;
		}
		else {
			ether_type = eth_hdr->type_length;
			ofs = sizeof(struct ethernet_hdr_s);
		}

		switch (ether_type) {
			case 0x800:
				/* IPv4 Packet */
				g_stats.num_ipv4_pkts++; 
				cont = parse_ipv4 (n, ofs, &ofs, &ip_hdr);	
				if (!cont) {
					continue;
				}

				switch (ip_hdr.proto) {
					case 6: 
						/* TCP */
						g_stats.num_tcp_pkts++;
						parse_tcp (n, ofs, &ofs, &ip_hdr, tstamp);
						n++;
						break;
			
					case 17: 
						g_stats.num_udp_pkts++;
						break;

					case 1: 
						g_stats.num_icmp_pkts++; 
						break; 

					default: 
						g_stats.num_not_tcp_udp_icmp_pkts++; 
				}
				break;
					
			case 0x86dd:
				/* IPv6 Packet */
				g_stats.num_ipv6_pkts++; 
				break;

			case 0x806:
				/* ARP */
				g_stats.num_arp_pkts++; 
				break;

			default:
				break;
		}
	}

	printf ("done.\n");	

	if (g_debug_flag) {
		print_counters (&g_stats);
	}

	fclose (fp);
	return 0;
}


#if COMPILE_AS_R_LIB

SEXP 
read_pcap_file (SEXP r_filename, SEXP r_debug)
{
	const char *fname;

	fname = CHAR(STRING_ELT(r_filename, 0));
	g_debug_flag = (int) REAL(r_debug)[0];

	init_state();
	parse_pcap_file (fname);
	return R_NilValue;
}


SEXP 
get_ipaddr_vector (void)
{
	struct ipv4_info_s *tmp;
	char ip_addr_str [32];
	SEXP vec;
	SEXP e;
	int i;

	vec = allocVector (STRSXP, g_num_list_elements);
	tmp = g_ipv4_list; 
	i = 0;

	while (tmp != NULL) {
		ip_to_str (ip_addr_str, 32, tmp->ip_addr);
		e = mkChar (ip_addr_str);
		SET_STRING_ELT (vec, i, e);
		tmp = tmp->next;		
		i++;
	}	
	return vec;
}


SEXP 
get_num_ip_pkts_sent_vector (void)
{
	struct ipv4_info_s *tmp;
	SEXP vec;
 	int i;

	vec = allocVector (REALSXP, g_num_list_elements);
	tmp = g_ipv4_list; 
	i = 0;

	while (tmp != NULL) {
		REAL(vec)[i] = (double)tmp->num_pkts_sent;
		tmp = tmp->next;		
		i++;
	}
    return vec;
}


SEXP 
get_num_ip_pkts_rcvd_vector (void)
{
	struct ipv4_info_s *tmp;
	SEXP vec;
	int i;

	vec = allocVector (REALSXP, g_num_list_elements);
	tmp = g_ipv4_list;
	i = 0;

	while (tmp != NULL) {
		REAL(vec)[i] = (double)tmp->num_pkts_rcvd;
		tmp = tmp->next;
		i++;
	}
	return vec;
}


SEXP 
get_tcp_init_ipaddr_vector (void)
{
	struct flow_s *tmp;
	char ip_addr_str [32];
	SEXP vec;
	SEXP e;
	uint32_t i, n = 0;

	vec = allocVector (STRSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			ip_to_str (ip_addr_str, 32, tmp->init_ip);
			e = mkChar (ip_addr_str);
			SET_STRING_ELT (vec, n, e);
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}


SEXP 
get_tcp_resp_ipaddr_vector (void)
{
	struct flow_s *tmp;
	char ip_addr_str [32];
	uint32_t i,n = 0;
	SEXP vec;
	SEXP e;

	vec = allocVector (STRSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			ip_to_str (ip_addr_str, 32, tmp->resp_ip);
			e = mkChar (ip_addr_str);
			SET_STRING_ELT (vec, n, e);
			tmp = tmp->next;
			n++;
		}
	}
	return vec;
}


SEXP 
get_tcp_init_port_vector (void)
{
	struct flow_s *tmp;
	uint32_t i, n = 0;
	SEXP vec;

	vec = allocVector (REALSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->init_port;
			tmp = tmp->next;
			n++;
		}	
	}
	return vec;
}


SEXP 
get_tcp_resp_port_vector (void)
{
	struct flow_s *tmp;
	uint32_t i, n = 0;
	SEXP vec;

	vec = allocVector (REALSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->resp_port;
			tmp = tmp->next;
			n++;
		}	
	}
	return vec;
}


SEXP 
get_flow_id_vector (void)
{
	struct flow_s *tmp;
	uint32_t i, n = 0;
	SEXP vec = NULL;

	vec = allocVector (REALSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->flow_id;
			tmp = tmp->next;		
			n++;
		}
	}
	return vec;
}


SEXP 
get_tcp_start_time_vector (void)
{
	struct flow_s *tmp;
	uint32_t i, n = 0;
	SEXP vec;

	vec = allocVector (REALSXP, g_stats.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < g_stats.num_tcp_flows; i++) {
		tmp = g_flow_table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->init_timestamps[0];
			tmp = tmp->next;
			n++;
		}	
	}
	return vec;
}


struct flow_s *
find_tcp_flow_by_id (uint32_t flow_id)
{
	int i;
	struct flow_s *tmp;

	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = g_flow_table[i];
		while (tmp != NULL) {
			if (tmp->l4_flow_type == TCP_FLOW && tmp->flow_id == flow_id) {
				return (tmp);
			}
			tmp = tmp->next;
		}
	}	
	return (NULL); 
}


SEXP 
get_tcp_flow_init_timestamps_vector (SEXP flow_id)
{
	int i;
	SEXP vec = NULL;
	uint64_t base_ts;
	struct flow_s *flow;
	uint32_t id = (unsigned int) REAL(flow_id)[0];

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->init_num_pkts);
		base_ts = flow->init_timestamps[0];
		for (i = 0; i < flow->init_num_pkts; i++) {
			REAL(vec)[i] = (double)(flow->init_timestamps[i] - base_ts);
		}
    }
    return vec;
}


SEXP 
get_tcp_flow_resp_timestamps_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	uint64_t base_ts = 0LL;
	struct flow_s *flow;
	SEXP vec = NULL;
	int i;

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		/* find first timestamp */
		base_ts = flow->resp_timestamps[0];

		vec = allocVector (REALSXP, flow->resp_num_pkts);
		for (i = 0; i < flow->resp_num_pkts; i++) {
			REAL(vec)[i] = (double)(flow->resp_timestamps[i] - base_ts);
		}
	}
	else {
		printf ("flow not found! id = %d\n", id);
	}
	return vec;
}



SEXP 
get_tcp_flow_init_ack_nums_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->init_num_pkts);
		for (i = 0; i < flow->init_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->init_ack_nums[i];
		}
	}
	return vec;
}


SEXP 
get_tcp_flow_init_seq_nums_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->init_num_pkts);
		for (i = 0; i < flow->init_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->init_seq_nums[i];
		}
	}
	return vec;
}

SEXP
get_tcp_flow_init_window_size_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->init_num_pkts);
		for (i = 0; i < flow->init_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->init_window_sizes[i];
		}
	}
	return vec;
}

SEXP 
get_tcp_flow_resp_ack_nums_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->resp_num_pkts);
		for (i = 0; i < flow->resp_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->resp_ack_nums[i];
		}
	}
	return vec;
}


SEXP 
get_tcp_flow_resp_seq_nums_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->resp_num_pkts);
		for (i = 0; i < flow->resp_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->resp_seq_nums[i];
		}
	}
	return vec;
}


SEXP
get_tcp_flow_resp_window_size_vector (SEXP flow_id)
{
	uint32_t id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;
	int i; 

	flow = find_tcp_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->resp_num_pkts);
		for (i = 0; i < flow->resp_num_pkts; i++) {
			REAL(vec)[i] = (double)flow->resp_window_sizes[i];
		}
	}
	return vec;
}

#else

int 
main (int argc, char *argv[])
{
    parse_pcap_file (argv[1]);
}

#endif

