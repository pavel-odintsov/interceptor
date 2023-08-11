/*
    Copyright: Pavel Odintsov
    Email: pavel.odintsov@gmail.com
*/

/* TODO:
    1)  Require SSE42
    2)  Require 64 bit platform
    3)  Packet crafting: http://dpdk.org/ml/archives/dev/2014-March/001590.html
    4)  Diabling timestamping on clent and server: echo 0 >  /proc/sys/net/ipv4/tcp_timestamps
    5)  Syn cookie on backend side should be checked explicitly!
    6)  Investogate why client send push with same seq as final ack! More details in txt file on desktop 
    7)  Fix code for work correctly with timestamping! Because it did not work!
    8)  Introduce fin flags processing 
    9)  Read RFC about tcp 
    10) Read mtcp article in Dropbox 
*/

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

#include <rte_ip.h>
#include <rte_tcp.h>

#include <crafter.h>

static rte_atomic32_t process_packets_until_exit;

/* TCP flags */
#define FIN_FLAG_SHIFT 0
#define SYN_FLAG_SHIFT 1
#define RST_FLAG_SHIFT 2
#define PUSH_FLAG_SHIFT 3
#define ACK_FLAG_SHIFT 4
#define URG_FLAG_SHIFT 5

/* According to specs we have 128 TX and RX queues for 82599 but we use only small amount of they */
#define MAX_RX_QUEUES_PER_PORT 16 
#define MAX_TX_QUEUES_PER_PORT 16

// We tune stack params like OpenVZ 2.6.32 kernel
unsigned int tcp_stack_default_ttl = 64;
unsigned int tcp_stack_max_segment_size = 1460;
unsigned int tcp_stack_window_size = 14480;
unsigned int tcp_stack_windows_scale = 7;

// We should maintain this params for each /32 host in our network!

uint16_t rx_queues = 1;
/* But for TX we need at least two queues */
uint16_t tx_queues = 2;

static struct rte_eth_conf default_port_conf;

void init_rte_eth_conf() {
    struct rte_eth_rxmode rxmode;
    struct rte_eth_txmode txmode; 

    rxmode.split_hdr_size = 0;
    rxmode.header_split   = 0; /* Header Split disabled */
    /* If we enable offload we will got error:
        Port[2] doesn't meet Vector Rx preconditions or RTE_IXGBE_INC_VECTOR is not enabled
    */
    rxmode.hw_ip_checksum = 0; /* IP/TCP/UDP checksum offload enabled */
    rxmode.hw_vlan_filter = 0; /* VLAN filtering disabled */
    rxmode.jumbo_frame    = 0; /* Jumbo Frame Support disabled */
    rxmode.hw_strip_crc   = 0; /* CRC stripped by hardware */

    txmode.mq_mode = ETH_MQ_TX_NONE, /* Disable any traffic distribution mode for TX */

    default_port_conf.txmode = txmode;
    default_port_conf.rxmode = rxmode;
};

static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static uint8_t working_ports[RTE_MAX_ETHPORTS];

void print_mac_address(struct ether_addr mac_address);
void print_mac_address(struct ether_addr mac_address) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
        mac_address.addr_bytes[0],
        mac_address.addr_bytes[1],
        mac_address.addr_bytes[2],
        mac_address.addr_bytes[3],
        mac_address.addr_bytes[4],
        mac_address.addr_bytes[5]);
}

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/* Simple implementation with one reader and writer */
/* We allocate it only for target port for testing purposes */
struct mbuf_table {
    unsigned len;
    struct rte_mbuf* m_table[MAX_PKT_BURST];
};


// This struct we will use for queueing data from already extablished connection with external client
struct mbuf_table incoming_queue_for_incoming_data;

union ipv4_5tuple_host {
        struct {
                uint8_t  pad0;
                uint8_t  proto;
                uint16_t pad1;
                uint32_t ip_src;
                uint32_t ip_dst;
                uint16_t port_src;
                uint16_t port_dst;
        };
        __m128i xmm;
};


#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

/* Mask for fast copy from IPv4 header to our key for flow tracking */
static __m128i mask0;

struct rte_hash* flow_tracking_lookup_struct = NULL;

// mbuf structures for forwarding between internal and external ports
struct mbuf_table interceptor_tx_mbuf_table_forwarding[RTE_MAX_LCORE];
// mbuf structures for conversation with internal and external clients
struct mbuf_table interceptor_tx_mbuf_table_conversation[RTE_MAX_LCORE];
struct rte_mempool* interceptor_pktmbuf_pool = NULL;

enum tcp_state {
    /* We have LISTEN state but did not use it */
    LISTEN       = 1,
    CLOSED       = 2,
    SYN_RECEIVED = 3,
    ESTABLISHED  = 4,
    SYN_SENT     = 5,   
    CLOSE_WAIT   = 6,
    LAST_ACK     = 7,
    FIN_WAIT_1   = 8,
    FIN_WAIT_2   = 9,
};


enum tcp_state external_client_connection_state = CLOSED;
enum tcp_state internal_client_connection_state = CLOSED;

// Here we store seq number for sirst external syn packet
uint32_t first_seq_number_from_external_client = 0;

/* Prototypes */
//void setup_flow_tracking_hash(void);
void calculate_ip_and_tcp_checksumms(struct ipv4_hdr* ipv4_hdr, struct tcp_hdr* tcp_hdr);
void init_diff_counters();
void rewrite_ack_and_seq_for_incoming_packet(struct tcp_hdr* tcp_hdr);
int extract_bit_value(uint8_t num, int bit);
void ether_header_src_dst_swap(struct ether_hdr* eth_hdr);
void ipv4_header_src_dst_swap(struct ipv4_hdr* ipv4_hdr);
void tcp_header_src_dst_port_swap(struct tcp_hdr* tcp_hdr);
void print_tcp_packet(struct ipv4_hdr* ipv4_hdr, struct tcp_hdr* tcp_hdr);
char* convert_ip_as_uint32_to_string(uint32_t ip);

char* convert_ip_as_uint32_to_string(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;

    return inet_ntoa(ip_addr);
}

void print_tcp_packet(struct ipv4_hdr* ipv4_hdr, struct tcp_hdr* tcp_hdr) {
    printf("src %s:%d dst %s:%d seq: %u ack: %u syn: %d ack: %d psh: %d\n",
        convert_ip_as_uint32_to_string(ipv4_hdr->src_addr), rte_be_to_cpu_16(tcp_hdr->src_port),
        convert_ip_as_uint32_to_string(ipv4_hdr->dst_addr), rte_be_to_cpu_16(tcp_hdr->dst_port), 
        rte_be_to_cpu_32(tcp_hdr->sent_seq),
        rte_be_to_cpu_32(tcp_hdr->recv_ack),
        extract_bit_value(tcp_hdr->tcp_flags, SYN_FLAG_SHIFT),
        extract_bit_value(tcp_hdr->tcp_flags, ACK_FLAG_SHIFT),
        extract_bit_value(tcp_hdr->tcp_flags, PUSH_FLAG_SHIFT)
   );
}

// Swap src and dst ports
void tcp_header_src_dst_port_swap(struct tcp_hdr* tcp_hdr) {
    uint16_t temp_port = tcp_hdr->src_port;
    tcp_hdr->src_port = tcp_hdr->dst_port;
    tcp_hdr->dst_port = temp_port;
}

// Swap src and dst addresses
// TODO: optimize this operations with rte_movXXX: http://dpdk.org/doc/api/rte__memcpy_8h.html!
void ipv4_header_src_dst_swap(struct ipv4_hdr*  ipv4_hdr) {
    uint32_t temp_ip = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = temp_ip;
}

// Swap src and dst for Ethernet frame
void ether_header_src_dst_swap(struct ether_hdr* eth_hdr) {
    struct ether_addr temp_addr;

    // From/to
    ether_addr_copy(&eth_hdr->s_addr, &temp_addr);
    ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
    ether_addr_copy(&temp_addr,       &eth_hdr->d_addr);
}

//static inline uint32_t
//ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
//        uint32_t init_val)
//{
//        const union ipv4_5tuple_host *k;
//        uint32_t t;
//        const uint32_t *p;
//
//        k = data;
//        t = k->proto;
//        p = (const uint32_t *)&k->port_src;
//
//#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
//        init_val = rte_hash_crc_4byte(t, init_val);
//        init_val = rte_hash_crc_4byte(k->ip_src, init_val);
//        init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
//        init_val = rte_hash_crc_4byte(*p, init_val);
//#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
//        init_val = rte_jhash_1word(t, init_val);
//        init_val = rte_jhash_1word(k->ip_src, init_val);
//        init_val = rte_jhash_1word(k->ip_dst, init_val);
//        init_val = rte_jhash_1word(*p, init_val);
//#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
//        return (init_val);
//}

/* default to 4 million hash entries (approx) */
/*
#define FLOW_TRACKING_HASH_ENTRIES              1024*1024*4
void setup_flow_tracking_hash(void) {
    struct rte_hash_parameters flow_tracking_hash_params = {
        .name = NULL,
        .entries = FLOW_TRACKING_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv4_5tuple_host),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    };

    char s[64];
    snprintf(s, sizeof(s), "flow_tracking_hash_%d", 11231);
    flow_tracking_hash_params.name = s;
    flow_tracking_hash_params.socket_id = rte_socket_id(); 

    flow_tracking_lookup_struct = rte_hash_create(&flow_tracking_hash_params); 

    if (flow_tracking_lookup_struct == NULL) {
        rte_exit(EXIT_FAILURE, "Unable to create flow tracking hash");
    }
}
*/

static int send_burst_to_port(uint8_t port_id, uint16_t tx_queue_id, struct mbuf_table* current_mbuf_table) {
    struct rte_mbuf **m_table = current_mbuf_table->m_table;
    unsigned packets_count = current_mbuf_table->len;

    unsigned ret = rte_eth_tx_burst(port_id, tx_queue_id, m_table, packets_count);

    /* Free up memory manually */
    if (unlikely(ret < packets_count)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < packets_count);
    } 

    return 0;
}

static int send_packet_to_port(struct rte_mbuf *m, struct mbuf_table* current_mbuf_table, uint8_t port_id, uint16_t tx_queue_id) {
    unsigned len = current_mbuf_table->len;
    current_mbuf_table->m_table[len] = m;
    len++;

    if (unlikely(len == MAX_PKT_BURST)) {
        //printf("Drain from send_packet\n");
        send_burst_to_port(port_id, tx_queue_id, current_mbuf_table);
        len = 0;
    }

    current_mbuf_table->len = len;
    return 0;
}


// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 7) {
        return (num >> bit) & 1;
    } else {
        return 0;
    }
}

static int client_validation_passed = 0;

// This seq number used by us when connect to external client
static rte_atomic64_t external_connection_seq_number;

// This seq number used by us when connecting to internal client
static rte_atomic64_t internal_connection_seq_number;

// It's most recent ACK received from external client
static rte_atomic64_t external_connection_client_seq_number;

// It's most recent ACK received from inetrnal client
static rte_atomic64_t internal_connection_backend_seq_number;

// It's most recent timestamp received from the external client
static rte_atomic64_t external_connection_client_timestamp;


// Flag because we should calculate they only once
rte_atomic16_t connection_seqence_diffs_calculated;

static rte_atomic64_t external_connection_seq_difference;
static rte_atomic64_t internal_connection_seq_difference;

static bool enable_debug_of_tcp_handshake = false;

static void forward_packet(int process_incoming_traffic, struct rte_mbuf* m,
    struct mbuf_table* current_mbuf_table,      unsigned forward_portid,        uint16_t forward_tx_queue_id,
    struct mbuf_table* conversation_mbuf_table, unsigned conversation_portid,   uint16_t conversation_tx_queue_id) {
    struct ether_hdr* eth_hdr  = rte_pktmbuf_mtod(m, struct ether_hdr*);

    int we_sent_conversation_packet = 0;

    // Switch to policy drop everything by default 
    int drop_paket = 1;

    bool drain_incoming_queue_to_internal_client = false;

    //printf("Traffic to port %d!!\n", forward_portid);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_IPv4) {
        struct ipv4_hdr* ipv4_hdr = (struct ipv4_hdr *)((char*)eth_hdr + sizeof(struct ether_hdr));
        uint16_t ip_header_len = (ipv4_hdr->version_ihl & 0x0f) * 4;

        if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
            /* Change TTL for example */
            // ipv4_hdr->time_to_live += 20;       
 
            struct tcp_hdr* tcp_hdr = (struct tcp_hdr*)((char*)ipv4_hdr + ip_header_len);

            //printf("Transit packet incoming thread: %d ", process_incoming_traffic); print_tcp_packet(ipv4_hdr, tcp_hdr);
            if (process_incoming_traffic) {
                // This process copy data from external port to internal

                if (external_client_connection_state == ESTABLISHED && internal_client_connection_state == ESTABLISHED) {
                    // Wnen we use random seq for connection to backed internal client we should do rewrite here
                    // We should change external requester sep by our internal!!!
                    //internal_connection_seq_number = internal_connection_seq_number + 1;
                    //tcp_hdr->sent_seq = rte_cpu_to_be_32(internal_connection_seq_number + 1); 
            
                    // Not a good idea do it here, we should calculate in another process
                    // init_diff_counters();
     
                    /*
                    1488429362/internal_connection_seq_difference + 981 341 959/ack     = 2 469 771 321/internal_connection_backend_seq_number
                    3 099 175 657/seq - 2714601710/external_connection_seq_difference   = 384 573 947/internal_connection_seq_number; 
                    */

                    rewrite_ack_and_seq_for_incoming_packet(tcp_hdr);

                    if (enable_debug_of_tcp_handshake) {
                        printf("We received packet from external network, process seq headers and sent it\n");
                        print_tcp_packet(ipv4_hdr, tcp_hdr);
                    }

                    //if (rte_atomic32_dec_and_test(&process_packets_until_exit)) {
                    //    rte_exit(EXIT_FAILURE, "limit packets processed, stop toolkit");
                    //}

                    // Pass traffic
                    // printf("We will bypass this traffic");
                    drop_paket = 0;
                } else if (external_client_connection_state == ESTABLISHED && internal_client_connection_state != ESTABLISHED) {
                    // Connection with external client already extablished but we could not receive data because
                    // internal client is not answered yet.
                    // Let's queue this packet

                    if (enable_debug_of_tcp_handshake) {
                        printf("We received packet on external interface, queue it\n");
                    }

                    // TODO: add locks
                    // But we can't fix ack and seq here because we do not know backed connection params :)
                    incoming_queue_for_incoming_data.m_table[incoming_queue_for_incoming_data.len] = m; 
                    incoming_queue_for_incoming_data.len++;

                    // Yes, not nice place for return but we do all tasks here and this return prevent any actions with packet
                    return;
                } else if (external_client_connection_state == CLOSED) {
                    // Check for syn flag 
                    if (extract_bit_value(tcp_hdr->tcp_flags, SYN_FLAG_SHIFT) == 1) {
                        if (enable_debug_of_tcp_handshake) {
                            print_tcp_packet(ipv4_hdr, tcp_hdr);
                            printf("SYN packet received\n");
                        }
                        
                        Crafter::Packet recv_packet;
                        recv_packet.PacketFromEthernet(rte_pktmbuf_mtod(m, const unsigned char*), rte_pktmbuf_pkt_len(m));

                        Crafter::Ethernet* recv_eth = recv_packet.GetLayer<Crafter::Ethernet>();
                        Crafter::IP* recv_ip   = recv_packet.GetLayer<Crafter::IP>();
                        Crafter::TCP* recv_tcp = recv_packet.GetLayer<Crafter::TCP>();
                        Crafter::TCPOptionTimestamp* recv_timestamp_opt = recv_packet.GetLayer<Crafter::TCPOptionTimestamp>();                       
                        if (!recv_timestamp_opt) {
                            printf("Can't read tcp timestamp\n");
                        }
 
                        // Build Ethernet packet
                        Crafter::Ethernet response_eth_header;
                        response_eth_header.SetDestinationMAC(recv_eth->GetSourceMAC());
                        response_eth_header.SetSourceMAC(recv_eth->GetDestinationMAC());
                        // 0x0800 - IP
                        response_eth_header.SetType(0x0800);
   
                        // Build IP packet 
                        Crafter::IP response_ip_header;
                        response_ip_header.SetSourceIP(      recv_ip->GetDestinationIP()  );
                        response_ip_header.SetDestinationIP( recv_ip->GetSourceIP()       );
                        response_ip_header.SetTTL(tcp_stack_default_ttl);                       

                        // Build TCP packet
                        Crafter::TCP tcp_header;

                        // Update global counters
                        rte_atomic64_set(&external_connection_seq_number, Crafter::RNG32());
                        //first_seq_number_from_external_client = rte_be_to_cpu_32(tcp_hdr->sent_seq);

                        tcp_header.SetAckNumber( recv_tcp->GetSeqNumber() + 1 ); 
                        tcp_header.SetSeqNumber( rte_atomic64_read(&external_connection_seq_number) ); 
   
                        if (enable_debug_of_tcp_handshake) { 
                            printf("external_connection_seq_number is: %ld\n", rte_atomic64_read(&external_connection_seq_number));
                        } 

                        tcp_header.SetSrcPort( recv_tcp->GetDstPort() );
                        tcp_header.SetDstPort( recv_tcp->GetSrcPort() );
                        tcp_header.SetFlags(Crafter::TCP::SYN | Crafter::TCP::ACK);
                            
                        Crafter::TCPOptionMaxSegSize maxseg;
                        maxseg.SetMaxSegSize(tcp_stack_max_segment_size);
            
                        Crafter::TCPOptionWindowScale wscale;
                        wscale.SetShift(tcp_stack_windows_scale);

                        Crafter::TCPOptionTimestamp tstamp;
                    
                        if (recv_timestamp_opt) {
                            // TODO: fix it
                            tstamp.SetValue(398303815); 
                        } else {
                            tstamp.SetValue(0);
                        }

                        /* a 4-byte echo reply timestamp value (the most recent timestamp received from you) */
                        /* I should put there latest timestamp received from client */
            
                        // TODO: this code will segfault in case of timestamp not defined in code
                        if (recv_timestamp_opt) {
                            tstamp.SetEchoReply(recv_timestamp_opt->GetValue());
                        } else {
                            tstamp.SetEchoReply(0);
                        }    

                        tcp_header.SetWindowsSize(tcp_stack_window_size);
                        Crafter::RawLayer payload("");

                        Crafter::Packet reponse_packet = response_eth_header / response_ip_header /
                            tcp_header /
                            /* START Option (padding should be controlled by the user) */
                            maxseg                              / // 4 bytes
                            Crafter::TCPOptionSACKPermitted()   / // 2 bytes
                            tstamp                              / // 10 bytes
                            Crafter::TCPOption::NOP             / // 1 byte
                            wscale                              / // 3 byte                   
                            // Crafter::TCPOption::EOL          / // 1 bytes
                            payload;

                        memcpy(rte_pktmbuf_mtod(m, void *), reponse_packet.GetRawPtr(), reponse_packet.GetSize());

                        if (rte_pktmbuf_pkt_len(m) < reponse_packet.GetSize()) {
                            // So I assume mbuf could fit my new packet and we need only change size pointers
                            // Update packet size
                            m->data_len = reponse_packet.GetSize();
                            m->pkt_len  = reponse_packet.GetSize();
                        }

                        if (enable_debug_of_tcp_handshake) {
                            printf("Send syn-ack packet to external client\n");
                            print_tcp_packet(ipv4_hdr, tcp_hdr);
                        }

                        external_client_connection_state = SYN_RECEIVED;

                        we_sent_conversation_packet = 1;
                        drop_paket = 0;
                    }
                } else if (external_client_connection_state == SYN_RECEIVED) {
                    // Well, we should check for ACK flag in packet
                    if (extract_bit_value(tcp_hdr->tcp_flags, ACK_FLAG_SHIFT) == 1) {

                        if (rte_be_to_cpu_32(tcp_hdr->recv_ack) == rte_atomic64_read(&external_connection_seq_number) + 1)  {
                            if (enable_debug_of_tcp_handshake) {
                                printf("Second ACK received. We received correct ack number. Connection established now!\n");
                                print_tcp_packet(ipv4_hdr, tcp_hdr);
                            }

                            external_client_connection_state = ESTABLISHED;

                            // store last seen seq from external client
                            rte_atomic64_set(&external_connection_client_seq_number, rte_be_to_cpu_32(tcp_hdr->sent_seq));
            
                            // reset flags
                            tcp_hdr->tcp_flags = 0;
                            // set SYN flag
                            tcp_hdr->tcp_flags |= 1 << SYN_FLAG_SHIFT;
                            // set ack to zero for SYN packet
                            tcp_hdr->recv_ack = 0;

                            // Well, we could use random seq
                            // internal_connection_seq_number = (uint32_t)rand();
                            // But we can use seq used by external client
                            //internal_connection_seq_number = first_seq_number_from_external_client;
                        
                            // Is more reliable way to use random seq for both directions
                            rte_atomic64_set(&internal_connection_seq_number, Crafter::RNG32());
                            tcp_hdr->sent_seq = rte_cpu_to_be_32(rte_atomic64_read(&internal_connection_seq_number)); 
 
                            // TODO: reduce packet size!

                            if (enable_debug_of_tcp_handshake) {
                                printf("We send SYN to backend\n");
                                print_tcp_packet(ipv4_hdr, tcp_hdr);
                            }        

                            // And then we send this packet to client
                            // And switch state machine to another status
                            internal_client_connection_state = SYN_SENT;
                            drop_paket = 0;
                        } else {
                            printf("Client validation failed :("); 
                        }
                    }
                }
            } else {
                // This process copy data from internal port to external
                if (internal_client_connection_state == SYN_SENT) {
                    // Check for SYN/ACK flags enabled
                    if (extract_bit_value(tcp_hdr->tcp_flags, SYN_FLAG_SHIFT) == 1 &&
                        extract_bit_value(tcp_hdr->tcp_flags, ACK_FLAG_SHIFT) == 1) {
                        
                        if (enable_debug_of_tcp_handshake) {
                            printf("Well, we received SYN/ACK from client\n");
                            print_tcp_packet(ipv4_hdr, tcp_hdr);
                        }

                        // Store last seen seq from internal client plus one because
                        rte_atomic64_set(&internal_connection_backend_seq_number, rte_be_to_cpu_32(tcp_hdr->sent_seq));

                        tcp_hdr->tcp_flags = 0;
                        // Set ack flag
                        tcp_hdr->tcp_flags |= 1 << ACK_FLAG_SHIFT;
            
                        // swap IPs, MACs and ports 
                        ether_header_src_dst_swap(eth_hdr);
                        ipv4_header_src_dst_swap(ipv4_hdr);
                        tcp_header_src_dst_port_swap(tcp_hdr);

                        rte_atomic64_inc(&internal_connection_seq_number);
                        tcp_hdr->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1);
                        tcp_hdr->sent_seq = rte_cpu_to_be_32(rte_atomic64_read(&internal_connection_seq_number));

                        if (enable_debug_of_tcp_handshake) {
                            printf("Send final ACK to backend\n");
                            print_tcp_packet(ipv4_hdr, tcp_hdr);

                            printf("Connection with internal established and we could use next seq: %u\n",
                                rte_atomic64_read(&internal_connection_seq_number));
                        }                        

                        internal_client_connection_state = ESTABLISHED;

                        // Well, now we really sure about established connection to backend client and could create diff pair :)
                        init_diff_counters();

                        // Drain all packets collected in incoming processor thread
                        drain_incoming_queue_to_internal_client = true;

                        we_sent_conversation_packet = 1;
                        drop_paket = 0;
                    }
                } else if (external_client_connection_state == ESTABLISHED && internal_client_connection_state == ESTABLISHED) {
                    if (!rte_atomic16_read(&connection_seqence_diffs_calculated)) {
                        rte_exit(EXIT_FAILURE, "HOLY SHIFT!!!! WE HAVENT DIFFS\n");
                    }

                    if (enable_debug_of_tcp_handshake) {
                        printf("internal_connection_seq_difference from back loop: %ld\n",
                            rte_atomic64_read(&internal_connection_seq_difference));
                        printf("external_connection_seq_difference from back loop: %ld\n",
                            rte_atomic64_read(&external_connection_seq_difference));
                    }
 
                    // We should rewrite seq and ack numbers to outside
                    int64_t new_seq = (int64_t)rte_be_to_cpu_32(tcp_hdr->sent_seq) - (int64_t)rte_atomic64_read(&internal_connection_seq_difference);
                    int64_t new_ack = (int64_t)rte_be_to_cpu_32(tcp_hdr->recv_ack) + (int64_t)rte_atomic64_read(&external_connection_seq_difference);
                    
                    if (new_seq < 0 or new_seq > UINT32_MAX) {
                        rte_exit(EXIT_FAILURE, "ALARM! back loop thread new seq %ld could not be negative or bigger than uint32\n", new_seq);
                    }

                    if (new_ack < 0 or new_ack > UINT32_MAX) {
                        rte_exit(EXIT_FAILURE, "ALARM! back loop thread new ack %ld could not be negative or bigger than uint32\n", new_ack);
                    }

                    tcp_hdr->sent_seq = rte_cpu_to_be_32( (uint32_t)new_seq);
                    tcp_hdr->recv_ack = rte_cpu_to_be_32( (uint32_t)new_ack);

                    if (enable_debug_of_tcp_handshake) {
                        printf("We received packet from the internal network, process seq/ack and sent it\n");
                        print_tcp_packet(ipv4_hdr, tcp_hdr);
                    }

                    //if (rte_atomic32_dec_and_test(&process_packets_until_exit)) {
                    //    rte_exit(EXIT_FAILURE, "limit packets processed, stop toolkit");
                    //} 

                    drop_paket = 0;
                }
            } 

            /*  

            // Flow tracking
            union ipv4_5tuple_host key;

            void* ipv4_hdr_for_lookup = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);
            __m128i data = _mm_loadu_si128((__m128i*)(ipv4_hdr_for_lookup));
            // Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol
            key.xmm = _mm_and_si128(data, mask0);

            // Find destination port 
            int32_t ret = rte_hash_lookup(flow_tracking_lookup_struct, (const void *)&key);

            if (ret >= 0) {
                // found flow
                // printf("We found old flow\n");
            } else {
                // not found flow
                //printf("Let's start new flow\n");
                int hash_add_ret = rte_hash_add_key(flow_tracking_lookup_struct, (void *)&key);
                    
                if (hash_add_ret < 0) {
                    //printf("Can't add key to hash\n");
                }
            }
            */

            /* Rewrite target port in TCP packet */

            calculate_ip_and_tcp_checksumms(ipv4_hdr, tcp_hdr);
        }

    } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
        drop_paket = 0;
    }

    // Drop packet: simply free buffer and return 
    if (drop_paket) {
        printf("I will drop this packet\n");
        rte_pktmbuf_free(m);
        return;
    } 

    if (drain_incoming_queue_to_internal_client) {
        drain_incoming_queue_to_internal_client = false;

        if (enable_debug_of_tcp_handshake) {
            printf("Drain packets from external queue from queue\n");
        }
        // We should extract data from this structur from head to tail!
        // Fix locking code here!!!!
        // Race conditions!
        for (unsigned int i = 0; i < incoming_queue_for_incoming_data.len; i++) {
            /* Remove this crap!! */
            struct ether_hdr* eth_hdr_temp  = rte_pktmbuf_mtod(incoming_queue_for_incoming_data.m_table[i], struct ether_hdr*);
            struct ipv4_hdr* ipv4_hdr_temp = (struct ipv4_hdr *)((char*)eth_hdr_temp + sizeof(struct ether_hdr));
            uint16_t ip_header_len_temp = (ipv4_hdr_temp->version_ihl & 0x0f) * 4;
            struct tcp_hdr* tcp_hdr_temp = (struct tcp_hdr*)((char*)ipv4_hdr_temp + ip_header_len_temp);

            rewrite_ack_and_seq_for_incoming_packet(tcp_hdr_temp);
            calculate_ip_and_tcp_checksumms(ipv4_hdr_temp, tcp_hdr_temp);

            send_packet_to_port(incoming_queue_for_incoming_data.m_table[i], conversation_mbuf_table,
                conversation_portid, conversation_tx_queue_id);
        }

        incoming_queue_for_incoming_data.len = 0;
    }

    if (we_sent_conversation_packet) {
        // Pass traffic back to sender
        send_packet_to_port(m, conversation_mbuf_table, conversation_portid, conversation_tx_queue_id); 
    } else {
        // Pass traffic without changes
        send_packet_to_port(m, current_mbuf_table, forward_portid, forward_tx_queue_id);
    }
}

static int packet_processor(void* arg) {
    unsigned lcore_id = rte_lcore_id();

    uint64_t prev_tsc = 0;
    uint64_t cur_tsc = 0; 
    uint64_t diff_tsc = 0;

    struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf* m = NULL;       

    uint8_t  source_port = 0;
    uint8_t  destination_port = 0;
    /* This port used for internal conversation with external or internal customers */
    uint8_t  answer_port = 0;

    /* We use separate queues for different tasks */
    uint16_t forwarding_tx_queue_id = 0;
    uint16_t answer_tx_queue_id = 1;

    int process_incoming_traffic = 0;

    if (lcore_id == 1) {
        /* Incoming traffic */
        source_port      = working_ports[0];
        destination_port = working_ports[1];
        answer_port      = working_ports[0];

        process_incoming_traffic = 1;
    } else if (lcore_id == 2) {
        /* Outgoing traffic */
        source_port      = working_ports[1];
        destination_port = working_ports[0];
        answer_port      = working_ports[1];

        process_incoming_traffic = 0;
    } else {
        /* Nothing to do on this lcore */
        return 0;
    }   

    printf("Worker thread started on %d code\n", lcore_id);
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    while (1) {
        // Get TSC times
        cur_tsc = rte_rdtsc();

        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            // Drain forward queue
            send_burst_to_port(destination_port, forwarding_tx_queue_id, &interceptor_tx_mbuf_table_forwarding[lcore_id]);
            interceptor_tx_mbuf_table_forwarding[lcore_id].len = 0;

            // Drain conversation queue
            send_burst_to_port(answer_port, answer_tx_queue_id, &interceptor_tx_mbuf_table_conversation[lcore_id]);
            interceptor_tx_mbuf_table_conversation[lcore_id].len = 0;
        }

        // Implement multiple queue
        for (uint16_t rx_queue_id = 0; rx_queue_id < rx_queues; rx_queue_id++) {  
            uint16_t rx_burst_packets_count = rte_eth_rx_burst(source_port, rx_queue_id, pkts_burst, MAX_PKT_BURST); 

            // According to this dump we do not need pull all queues, all traffic arrived to 0 queue
            // But we should check it
            if (rx_burst_packets_count != 0) {
                //printf("port %d queue %d packets %d\n", source_port, rx_queue_id, rx_burst_packets_count);
            }

            for (unsigned int j = 0; j < rx_burst_packets_count; j++) {
                m = pkts_burst[j];
                /* mtod provide pointer to the packet data */
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));

                forward_packet(process_incoming_traffic, m,
                    &interceptor_tx_mbuf_table_forwarding[lcore_id], destination_port, forwarding_tx_queue_id,
                    &interceptor_tx_mbuf_table_conversation[lcore_id], answer_port, answer_tx_queue_id
                );
            }
        }
    } 

    return 0;
}

// This execute rewrite for inconing packets with fixed shift
void rewrite_ack_and_seq_for_incoming_packet(struct tcp_hdr* tcp_hdr) {
    if (!rte_atomic16_read(&connection_seqence_diffs_calculated)) {
        rte_exit(EXIT_FAILURE, "HOLY SHIFT!!!! WE HAVENT DIFFS for calculation in rewrite_ack_and_seq_for_incoming_packet\n");
    }

    int64_t new_seq = (int64_t)rte_be_to_cpu_32(tcp_hdr->sent_seq) - (int64_t)rte_atomic64_read(&external_connection_seq_difference);
    int64_t new_ack = (int64_t)rte_be_to_cpu_32(tcp_hdr->recv_ack) + (int64_t)rte_atomic64_read(&internal_connection_seq_difference);

    if (enable_debug_of_tcp_handshake) {
        printf("raw ack: %u and seq %u\n", rte_be_to_cpu_32(tcp_hdr->recv_ack), rte_be_to_cpu_32(tcp_hdr->sent_seq));
        printf("ack ops: +%ld seq ops: -%ld\n",
            (int64_t)rte_atomic64_read(&internal_connection_seq_difference), 
            (int64_t)rte_atomic64_read(&external_connection_seq_difference));

        printf("new ack: %ld new seq: %ld\n", new_ack, new_seq);
    }        

    if (new_seq < 0 or new_seq > UINT32_MAX) {
        rte_exit(EXIT_FAILURE, "ALARM! new seq %ld could not be negative or bigger than uint32\n", new_seq);
    }    

    if (new_ack < 0 or new_ack > UINT32_MAX) {
        rte_exit(EXIT_FAILURE, "ALARM! new ack %ld could not be negative or bigger than uint32\n", new_ack);
    }    

    // Set new seq/ack numbers to packet
    tcp_hdr->sent_seq = rte_cpu_to_be_32( (uint32_t)new_seq);
    tcp_hdr->recv_ack = rte_cpu_to_be_32( (uint32_t)new_ack);
}  

void init_diff_counters() { 
    if (!rte_atomic16_read(&connection_seqence_diffs_calculated)) { 
        if ((int64_t)rte_atomic64_read(&external_connection_client_seq_number) == 0) {
            rte_exit(EXIT_FAILURE, "external_connection_client_seq_number is zero!!!");       
        }

        if ((int64_t)rte_atomic64_read(&internal_connection_seq_number) == 0) {
            rte_exit(EXIT_FAILURE, "internal_connection_seq_number is zero!!!");
        }
   
        if ((int64_t)rte_atomic64_read(&internal_connection_backend_seq_number) == 0) {
            rte_exit(EXIT_FAILURE, "internal_connection_backend_seq_number is zero!!!");
        }

        if ((int64_t)rte_atomic64_read(&external_connection_seq_number) == 0) {
            rte_exit(EXIT_FAILURE, "external_connection_seq_number is zero!!!");
        }
 
        rte_atomic64_set(&external_connection_seq_difference, (int64_t)rte_atomic64_read(&external_connection_client_seq_number)  -
            (int64_t)rte_atomic64_read(&internal_connection_seq_number));
        rte_atomic64_set(&internal_connection_seq_difference, (int64_t)rte_atomic64_read(&internal_connection_backend_seq_number) -
            (int64_t)rte_atomic64_read(&external_connection_seq_number)); 

        rte_atomic16_set(&connection_seqence_diffs_calculated, 1);

        if (enable_debug_of_tcp_handshake) {
            printf("external_connection_client_seq_number:\t%ld\n",
                rte_atomic64_read(&external_connection_client_seq_number));
            printf("internal_connection_seq_number:\t\t%ld\n",
                rte_atomic64_read(&internal_connection_seq_number));

            printf("internal_connection_backend_seq_number:\t%ld\n",
                rte_atomic64_read(&internal_connection_backend_seq_number));
            printf("external_connection_seq_number:\t\t%ld\n",
                rte_atomic64_read(&external_connection_seq_number));

            printf("external_connection_seq_difference:\t%ld\n",
                rte_atomic64_read(&external_connection_seq_difference));
            printf("internal_connection_seq_difference:\t%ld\n",
                rte_atomic64_read(&internal_connection_seq_difference));
        }        
    }                
}  

void calculate_ip_and_tcp_checksumms(struct ipv4_hdr* ipv4_hdr, struct tcp_hdr* tcp_hdr) {
    /* Hint for NIC: we sent IP packet */
    //m->ol_flags |= PKT_TX_IPV4;
    //m->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;

    /* Recalculate checksumm for IPv4 packet */
    /* It's required by rte_ipv4_cksum and hardware offload */
    ipv4_hdr->hdr_checksum = 0;
    tcp_hdr->cksum = 0;
    // fake for offload mode
    //tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr, m->ol_flags);
    tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);

    // Calculate cheksum in software
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    /* It's required for offload too */
    //m->l2_len = sizeof(struct ether_hdr);
    //m->l3_len = sizeof(struct ipv4_hdr);
    //m->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
    /* Send data to target port */
    // printf("Interseptor incoming thread: %d send packet: ", process_incoming_traffic);
    // print_tcp_packet(ipv4_hdr, tcp_hdr);
}

int main(int argc, char **argv) {
    init_rte_eth_conf();
   
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    } 

    rte_atomic32_init(&process_packets_until_exit);
    rte_atomic32_set(&process_packets_until_exit, 500);

    rte_atomic16_init(&connection_seqence_diffs_calculated);
    rte_atomic16_clear(&connection_seqence_diffs_calculated);

    rte_atomic64_init(&external_connection_seq_number);
    rte_atomic64_set(&external_connection_seq_number, 0);

    rte_atomic64_init(&internal_connection_seq_number);
    rte_atomic64_set(&internal_connection_seq_number, 0);

    rte_atomic64_init(&external_connection_seq_difference);
    rte_atomic64_set(&external_connection_seq_difference, 0);
    
    rte_atomic64_init(&internal_connection_seq_difference);
    rte_atomic64_set(&internal_connection_seq_difference, 0);

    rte_atomic64_init(&external_connection_client_seq_number);
    rte_atomic64_set(&external_connection_client_seq_number, 0);

    rte_atomic64_init(&internal_connection_backend_seq_number);
    rte_atomic64_set(&internal_connection_backend_seq_number, 0);
        
    /* Add space between DPDK EAL init and our toolkit */
    printf("\n\n");

    printf("Allocate memory for application\n");

    /* TODO: investigate it! */
    /* The optimum size (in terms of memory usage) for a mempool is when n is a power of two minus one: n = (2^q - 1) */
    unsigned int number_of_elements = 8192;
    unsigned int size_of_element = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
    unsigned int cache_size = 32;
    
    interceptor_pktmbuf_pool = rte_mempool_create("mbuf_pool",
        number_of_elements, size_of_element, cache_size, sizeof(struct rte_pktmbuf_pool_private),
        rte_pktmbuf_pool_init, NULL,
        rte_pktmbuf_init, NULL,
        rte_socket_id(), 0
    );

    if (interceptor_pktmbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot allocate memory pool for application\n");
    }

    /* For filter mode we need 2 ports */ 
    uint8_t minimum_required_ports = 2;

    /* How much ports we have available for DPDK */
    uint8_t available_ports = rte_eth_dev_count();
    printf("We have %d active ports for DPDK\n", available_ports);
   
    if (available_ports < minimum_required_ports) {
        rte_exit(EXIT_FAILURE, "We need least 2 available ports for correct operation\n");
    }
 
    /* Check ports link status */
    printf("Check link status for all ports\n");
    uint8_t active_ports = 0;

    for (uint8_t port_number = 0; port_number < available_ports; port_number++) {
        struct rte_eth_link link;

        /* We use _nowait version for fast operations */
        rte_eth_link_get_nowait(port_number, &link);

        printf("Port: %d speed: %d link duplex: %d link status: %d\n", port_number, link.link_speed, link.link_duplex, link.link_status);

        if (link.link_status == 1 && link.link_speed == 10000 && link.link_duplex == ETH_LINK_FULL_DUPLEX) {
            printf("We will use port %d because it has correct speed, duplex and active link\n", port_number);
            working_ports[active_ports++] = port_number;
        }
    } 

    if (active_ports < minimum_required_ports) {
        rte_exit(EXIT_FAILURE, "We need least 2 active ports for correct operation\n");
    }

    printf("Well, we have required number of active 10GE ports: ");
    for (uint8_t port_index = 0; port_index < minimum_required_ports; port_index++) {
        printf("%d ", working_ports[port_index]);
    }   

    printf("\n");

    /* Initialize ports */
    for (uint8_t port_index = 0; port_index < minimum_required_ports; port_index++) {
        uint8_t  current_port = working_ports[port_index]; 
 
        int eth_configure_ret = rte_eth_dev_configure(current_port, rx_queues, tx_queues, &default_port_conf);

        if (eth_configure_ret != 0) {
            rte_exit(EXIT_FAILURE, "Can't configure port %d\n", working_ports[port_index]);
        }

        printf("Port %d initilized correctly\n", working_ports[port_index]);

        /* Get MAC address for device */
        rte_eth_macaddr_get(current_port, &ports_eth_addr[port_index]);
        printf("MAC address of interface from %d port is: ", current_port);
        print_mac_address(ports_eth_addr[port_index]);

        /* Number of RX/TX ring descriptors */
        /* TODO: why this numbers ... ? */
        uint16_t number_rx_descriptors = 128;
        uint16_t number_tx_descriptors = 512;
 
        /* Initialize RX queues */
        
        for (uint16_t rx_queue_id = 0; rx_queue_id < rx_queues; rx_queue_id++) {
            int rx_queue_ret = rte_eth_rx_queue_setup(current_port, rx_queue_id, number_rx_descriptors,
                rte_eth_dev_socket_id(current_port), NULL, interceptor_pktmbuf_pool);

            if (rx_queue_ret != 0) {
                rte_exit(EXIT_FAILURE, "Can't configure RX queue %d for port %d\n", rx_queue_id, current_port);
            } 
        }

        /* Initialize TX queues */
        for (uint16_t tx_queue_id = 0; tx_queue_id < tx_queues; tx_queue_id++) {
            int tx_queue_ret = rte_eth_tx_queue_setup(current_port, tx_queue_id, number_tx_descriptors,
                rte_eth_dev_socket_id(current_port), NULL);

            if (tx_queue_ret != 0) {
                rte_exit(EXIT_FAILURE, "Can't configure TX queue %d for port %d\n", tx_queue_id, current_port);
            }
        }

        /* Start device */
        int start_device_ret = rte_eth_dev_start(current_port);

        if (start_device_ret != 0) {
            rte_exit(EXIT_FAILURE, "Can't start device %d\n", current_port);
        }

        /* Switch port to promisc mode */
        /* We definitely need this because we could intercept traffic without transparently */
        rte_eth_promiscuous_enable(current_port);
    
        /* Check hardware NIC offlaod features because we relay on it */
        struct rte_eth_dev_info dev_info;

        rte_eth_dev_info_get(current_port, &dev_info);
            
        /* Check TX offload capabilities */
        if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "NIC in port %d hasn't IP checksum TX offload capability\n", current_port);
        }

        if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "NIC in port %d hasn't TCP checksum TX offload capability\n", current_port);   
        }

        /* Check RX offload capabilities */
        if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "NIC in port %d hasn't IP checksum RX offload capability\n", current_port);
        }

        if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "NIC in port %d hasn't TCP checksum RX offload capability\n", current_port);
        }
    }

    /* Zeroify memory for packets */
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
        interceptor_tx_mbuf_table_forwarding[i].len = 0;
        interceptor_tx_mbuf_table_conversation[i].len = 0;
    }

    incoming_queue_for_incoming_data.len = 0;

    /* Setup flow tracking hash */
    //setup_flow_tracking_hash();

    mask0 = _mm_set_epi32(ALL_32_BITS, ALL_32_BITS, ALL_32_BITS, BIT_8_TO_15);
 
    unsigned lcore_id;
    /* call packet_processor() on every slave lcore */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) { 
        rte_eal_remote_launch(packet_processor, NULL, lcore_id);
    }

    rte_eal_mp_wait_lcore();
    return 0;
}
