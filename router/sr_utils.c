#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_nat.h"
#include <assert.h>
uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf);
  return ip_hdr->ip_p;
}


/* Prints out nat mapping entry */ 
void print_nat_mapping (struct sr_nat_mapping* nat_mapping) {
  print_addr_ip_int(nat_mapping->ip_int);
  print_addr_ip_int(nat_mapping->ip_ext);
  print_addr_ip_int(nat_mapping->aux_int);
  print_addr_ip_int(nat_mapping->aux_ext);
  return; 
}

void print_nat_table (struct sr_nat *nat) {
	struct sr_nat_mapping *curr_mapping = nat->mappings;
	assert (curr_mapping != NULL);
	while (!curr_mapping) {
		print_nat_mapping (curr_mapping);
		curr_mapping = curr_mapping->next;  
	}
	return;	

}

uint32_t ip_cksum (sr_ip_hdr_t *ipHdr, int len) {
    uint16_t currChksum, calcChksum;
    currChksum = ipHdr->ip_sum; 
    ipHdr->ip_sum = 0;
    calcChksum = cksum(ipHdr, len);
    ipHdr->ip_sum = currChksum;    

    return calcChksum;
}

uint32_t tcp_cksum(sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr, int total_len) {

  uint8_t *full_tcp;
  sr_tcp_psuedo_hdr_t *tcp_psuedo_hdr;

  int tcp_len = total_len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  int full_tcp_len = sizeof(sr_tcp_psuedo_hdr_t) + tcp_len;

  tcp_psuedo_hdr = malloc(sizeof(sr_tcp_psuedo_hdr_t));
  memset(tcp_psuedo_hdr, 0, sizeof(sr_tcp_psuedo_hdr_t));

  tcp_psuedo_hdr->ip_src = ip_hdr->ip_src;
  tcp_psuedo_hdr->ip_dst = ip_hdr->ip_dst;
  tcp_psuedo_hdr->ip_p = ip_hdr->ip_p;
  tcp_psuedo_hdr->tcp_len = htons(tcp_len);

  uint16_t currCksum = tcp_hdr->tcp_sum;
  tcp_hdr->tcp_sum = 0;

  full_tcp = malloc(sizeof(sr_tcp_psuedo_hdr_t) + tcp_len);
  memcpy(full_tcp, (uint8_t *) tcp_psuedo_hdr, sizeof(sr_tcp_psuedo_hdr_t));
  memcpy(&(full_tcp[sizeof(sr_tcp_psuedo_hdr_t)]), (uint8_t *) tcp_hdr, tcp_len);
  tcp_hdr->tcp_sum = currCksum;

  uint16_t calcCksum = cksum(full_tcp, full_tcp_len);

  /* Clear out memory used for creation of complete tcp packet */
  free(tcp_psuedo_hdr);
  free(full_tcp);

  return calcCksum;
}

uint32_t icmp_cksum (sr_icmp_hdr_t *icmpHdr, int len) {
    uint16_t currChksum, calcChksum;

    currChksum = icmpHdr->icmp_sum; 
    icmpHdr->icmp_sum = 0;
    calcChksum = cksum(icmpHdr, len);
    icmpHdr->icmp_sum = currChksum;

    return calcChksum;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", ip_hdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", ip_hdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", ip_hdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(ip_hdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(ip_hdr->ip_id));

  if (ntohs(ip_hdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(ip_hdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(ip_hdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(ip_hdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", ip_hdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", ip_hdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", ip_hdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(ip_hdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);

fprintf(stderr, "\tid: %d\n", icmp_hdr->icmp_id);
fprintf(stderr, "\tseq: %d\n", icmp_hdr->icmp_seq);

}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

