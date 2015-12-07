
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define NAT_INTERNAL_INTERFACE "eth1"

#define MAX_16B_NUM 65535

#define MIN_TCP_PORT 1024
#define TOTAL_TCP_PORTS MAX_16B_NUM - MIN_TCP_PORT

#define MIN_ICMP_IDENTIFIER 1
#define TOTAL_ICMP_IDENTIFIERS MAX_16B_NUM - MIN_ICMP_IDENTIFIER

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum
{
   SYN_SENT, /**< outbound SYN sent. */
   SYN_RCVD, /**< inbound SYN received (and queued). */
   ESTABLISHED, /**< SYNs sent in both directions. Connection established. */
   TIME_WAIT /**< One of the endpoints has sent a FIN. */
} sr_nat_tcp_conn_state_t;

struct sr_nat_connection {
    /* add TCP connection state data members here */
    struct {
      uint32_t ip_addr;
      uint16_t port_num;
    } external;
   
    sr_ip_hdr_t * inboundSyn;
    time_t last_updated;
    /*sr_tcp_state tcp_state;*/
    sr_nat_tcp_conn_state_t tcp_conn_state;
    struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  /* Timeout */
  unsigned int icmp_query_timeout;
  unsigned int tcp_estb_timeout;
  unsigned int tcp_trns_timeout;

  /* Mapping of available ICMP identifiers */
  uint16_t free_icmp_identifiers[TOTAL_ICMP_IDENTIFIERS];
  uint16_t free_tcp_ports[TOTAL_TCP_PORTS];


  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

int sr_nat_is_interface_internal(char *interface); 

int sr_nat_generate_icmp_identifier(struct sr_nat *nat);

struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat_mapping *nat_mapping, uint32_t ip_ext, uint16_t port_ext);

int sr_nat_generate_tcp_port(struct sr_nat *nat);


void sr_nat_destroy_mapping(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping);

void check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping);

void sr_nat_destroy_connection(struct sr_nat_mapping* nat_mapping, struct sr_nat_connection* connection); 

#endif
