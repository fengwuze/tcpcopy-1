#ifndef  XCOPY_H_INCLUDED
#define  XCOPY_H_INCLUDED

#include <tc_auto_config.h>
#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#if (TC_UDP)
#include <netinet/udp.h>
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#if (TC_OFFLINE || TC_PCAP || TC_PCAP_SND)
#include <pcap.h>
#endif

#if (TC_ADVANCED)
#define TC_DR 1
#endif

#if (TC_OFFLINE)
#undef TC_PCAP
#endif

#define VERSION "1.0.0"  

#define INTERNAL_EVOLUTION_VERSION 5 
#if (TC_ADVANCED)
#define INTERNAL_VERSION (32768 + INTERNAL_EVOLUTION_VERSION)
#else
#define INTERNAL_VERSION INTERNAL_EVOLUTION_VERSION
#endif

typedef struct tc_cmd_s         tc_cmd_t;
typedef struct tc_module_s      tc_module_t;
typedef struct tc_pool_s        tc_pool_t;
typedef struct tc_conf_s        tc_conf_t;
typedef struct tc_file_s        tc_file_t;
typedef struct tc_buf_s         tc_buf_t;
typedef struct tc_array_s       tc_array_t;
typedef struct tc_sess_s        tc_sess_t;


#define COPY_FROM_IP_LAYER 0
#define COPY_FROM_LINK_LAYER 1

#define ETHER_ADDR_LEN 0x6


#ifndef TC_CPU_CACHE_LINE
#define TC_CPU_CACHE_LINE  64
#endif

#define IP_RCV_BUF_SIZE 65536
#define PCAP_RCV_BUF_SIZE 65535
#define MAX_FILTER_LENGH 4096 
#define M_IP_NUM 4096

#define SESS_TABLE_POOL_SIZE 1048576
#define TC_PCAP_BUF_SIZE 16777216

#define TC_MAX_ALLOC_FROM_POOL  (tc_pagesize - 1)

#define TC_UPOOL_LOOP_THRESH 255
#define TC_UPOOL_LOOP_SIZE (32 * 1024)
#define TC_UPOOL_MAXV 1023
#define TC_DEFAULT_POOL_SIZE    (16 * 1024)
#define TC_DEFAULT_UPOOL_SIZE    (4 * 1024)
#define TC_REDUCED_UPOOL_SIZE    (2 * 1024)
#define TC_MID_UPOOL_SIZE_THRESH (16 * 1024)
#define TC_MIN_UPOOL_SIZE_THRESH (64 * 1024)

#define TC_POOL_ALIGNMENT       16
#define TC_MIN_POOL_SIZE                                                     \
        tc_align((sizeof(tc_pool_t) + 2 * sizeof(tc_pool_large_t)),          \
                              TC_POOL_ALIGNMENT)


#define DEFAULT_MTU   1500
#define DEFAULT_MSS   1460
#define MAX_CHECKED_MTU 2048

/* default listening port for intercept */
#define SERVER_PORT   36524


#if (TC_DR)
#define MAX_REAL_SERVERS 32
#endif

#define DEAD_LOCK_MS_TIMEOUT 100
#define TCP_MS_TIMEOUT 6000
#define SESS_EST_MS_TIMEOUT 3000
#define OUTPUT_INTERVAL  30000
#define RETRY_INTERVAL  12000

#define CHECK_INTERVAL  5
#define OFFLINE_ACTIVATE_INTERVAL  10
#define DEFAULT_TIMEOUT 1200
#define DEFAULT_SESS_TIMEOUT 120
#define OFFLINE_TAIL_TIMEOUT 120 

#define MAX_WRITE_TRIES 1024
#define MAX_READ_LOG_TRIES 65536

#if (TC_MILLION_SUPPORT)
#define CHECK_SESS_TIMEOUT 30000
#define SESS_KEEPLIVE_ADD 1200
#else
#define CHECK_SESS_TIMEOUT 6000
#define SESS_KEEPLIVE_ADD 120
#endif

#define MAX_SLIDE_WIN_THRESH 32768
#define SND_TOO_SLOW_THRESH 64

/* max fd number for select */
#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM - 1)
#define MAX_CONN_NUM 11
#define MAX_SINGLE_CONN_NUM 16

#if (TC_COMBINED)
#if (TC_PAYLOAD) 
#define COMB_MAX_NUM 6
#define MAX_PAYLOAD_LEN  128
#else
#define COMB_MAX_NUM 16
#endif
#define COMB_LENGTH (COMB_MAX_NUM * MSG_SERVER_SIZE)
#define TIME_DRIVEN 1
#define NUM_DRIVEN 2
#endif

#define SRC_DIRECTION 0
#define DST_DIRECTION 1
#define MAX_FILTER_ITEMS 32
#define MAX_FILTER_PORTS 32
#define MAX_FILTER_IPS 32
#define MAX_DEVICE_NUM 32
#define MAX_DEVICE_NAME_LEN 32

#define MAX_ALLOWED_IP_NUM 32

/* in defence of occuping too much memory */
#define MAX_MEMORY_SIZE 1048576

/* route flags */
#define  CLIENT_ADD   1
#define  CLIENT_DEL   2

#define PAYLOAD_FULL 1
#define PAYLOAD_NOT_FULL 2

#define CHECK_DEST 1
#define CHECK_SRC  2

#define TYPE_DELAY_ACK 0
#define TYPE_TIMEOUT 1
#define TYPE_RECONSTRUCT 2

#define PACK_STOP      0
#define PACK_CONTINUE  1
#define PACK_NEXT      2
#define PACK_SLIDE     4

#define TC_CONF_NOARGS      0x00000001
#define TC_CONF_TAKE1       0x00000002
#define TC_CONF_TAKE2       0x00000004
#define TC_CONF_TAKE3       0x00000008

#define TC_CONF_MAX_ARGS    8

#define TC_CONF_TAKE12      (TC_CONF_TAKE1|TC_CONF_TAKE2)
#define TC_CONF_TAKE13      (TC_CONF_TAKE1|TC_CONF_TAKE3)
#define TC_CONF_TAKE23      (TC_CONF_TAKE2|TC_CONF_TAKE3)
#define TC_CONF_TAKE123     (TC_CONF_TAKE1|TC_CONF_TAKE2|TC_CONF_TAKE3)

#define TC_CONF_FLAG        0x00000200
#define TC_CONF_ANY         0x00000400
#define TC_CONF_1MORE       0x00000800
#define TC_CONF_2MORE       0x00001000

#define TCPH_DOFF_MIN_VALUE 5
#define TCPH_DOFF_MSS_VALUE 6
#define TCPH_DOFF_TS_VALUE 8
#define TCPH_DOFF_WS_TS_VALUE 9
#define IPH_MIN_LEN sizeof(tc_iph_t)
#define TCPH_MIN_LEN sizeof(tc_tcph_t)
#define TCP_IP_PACK_MIN_LEN (IPH_MIN_LEN + TCPH_MIN_LEN)

#define OBSOLETE 1
#define CANDIDATE_OBSOLETE -1
#define NOT_YET_OBSOLETE 0

#define RTT_INIT 0
#define RTT_FIRST_RECORED 1
#define RTT_CAL 2

typedef volatile sig_atomic_t tc_atomic_t;

typedef struct iphdr  tc_iph_t;
typedef struct tcphdr tc_tcph_t;
#if (TC_UDP)
typedef struct udphdr tc_udpt_t;
#endif

/* 
 * 40 bytes available for TCP options 
 * we support 24 bytes for TCP options
 */
#define MAX_OPTION_LEN 24
#define MAX_TCP_LEN_SUPPORTED (sizeof(tc_tcph_t) + MAX_OPTION_LEN)
#define TCPOPT_WSCALE 3

#define REP_HEADER_SIZE (sizeof(tc_iph_t) + MAX_TCP_LEN_SUPPORTED)
#if (TC_PAYLOAD)
#define REP_MAX_USEFUL_SIZE (REP_HEADER_SIZE + MAX_PAYLOAD_LEN)
#else
#define REP_MAX_USEFUL_SIZE REP_HEADER_SIZE
#endif

/* bool constants */
#if (HAVE_STDBOOL_H)
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif /* HAVE_STDBOOL_H */ 

enum sess_status{
    CLOSED       = 0,
    SYN_SENT     = 1,
    SYN_CONFIRM  = 2,
    ESTABLISHED  = 4,
    SND_REQ     = 8,
    RCV_REP    = 16,
    SERVER_FIN   = 32,
    CLIENT_FIN   = 64
};

enum packet_classification{
    TC_CLT,
    TC_BAK,
    TC_TO_BAK,
    TC_UNKNOWN
};

#define ETHER_ADDR_STR_LEN 17

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16
#define ETHERNET_HDR_LEN (sizeof(struct ethernet_hdr))
#define DEFAULT_DEVICE     "any"

/*  
 *  Ethernet II header
 *  static header size: 14 bytes          
 */ 
struct ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};


#if (TC_PCAP)
typedef struct device_s{
    char    name[MAX_DEVICE_NAME_LEN];
    pcap_t *pcap;
}device_t;

typedef struct devices_s{
    int       device_num;
    device_t  device[MAX_DEVICE_NUM];
}devices_t;
#endif

typedef struct connections_s{
    short active;
    uint16_t port;
    uint32_t ip;
    int index; 
    int num;
    int remained_num;
    int fds[MAX_CONN_NUM];
}conns_t;

/* global functions */
int daemonize();
static inline int before(uint32_t seq1, uint32_t seq2)
{
    return (int) ((uint32_t) (seq1-seq2)) < 0;
}


#if (TC_PLUGIN)
struct tc_module_s{
    void      *ctx;
    tc_cmd_t  *cmds;
    int      (*init_module)(void *clt_settings);
    void     (*exit_module)(void *clt_settings);
    bool     (*check_padding)(tc_iph_t *, tc_tcph_t *); 
    int      (*prepare_renew)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    bool     (*check_pack_for_renew)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    int      (*proc_when_sess_created)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    int      (*proc_when_sess_destroyed)(tc_sess_t *, tc_iph_t *, tc_tcph_t *);
    int      (*proc_greet)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    int      (*proc_auth)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    int      (*post_auth)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
    int      (*adjust_clt_seq)(tc_sess_t *, tc_iph_t *, tc_tcph_t *); 
};
#endif

#define after(seq2, seq1) before(seq1, seq2)

#define TC_OK      0
#define TC_ERR    -1
#define TC_ERR_EXIT  1
#define TC_DELAYED  -2

#define tc_cpymem(d, s, l) (((char *) memcpy(d, (void *) s, l)) + (l))
#define tc_memzero(d, l) (memset(d, 0, l))

#define tc_abs(value)       (((value) >= 0) ? (value) : - (value))
#define tc_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define tc_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
#define tc_string(str)     { sizeof(str) - 1, (u_char *) str }

#include <tc_config.h>
#include <tc_link_list.h>
#include <tc_hash.h>
#include <tc_time.h>
#include <tc_rbtree.h>
#include <tc_signal.h>

#include <tc_log.h>
#include <tc_msg.h>
#include <tc_socket.h>
#include <tc_util.h>
#if (TC_DIGEST)
#include <tc_evp.h>
#endif
#include <tc_alloc.h>
#include <tc_palloc.h>
#include <tc_event.h>
#include <tc_array.h>
#include <tc_conf_file.h>
#include <tc_select_module.h>
#include <tc_event_timer.h>

#endif /* XCOPY_H_INCLUDED */

