
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_utils.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
 /* struct sr_nat_mapping *head;*/ 
  return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  printf  ("NAT lookup given external port \n");
  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *curr_mapping, *target_mapping = NULL;
  curr_mapping = nat->mappings;

  while (curr_mapping != NULL) {
    printf ("[NAT] iterating over the NAT table... \n");   
    if (curr_mapping->type == type && curr_mapping->aux_ext == aux_ext) {
      target_mapping = curr_mapping;
      break;
    }
    curr_mapping = curr_mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return target_mapping;

}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  printf  ("NAT lookup given internal port \n");
  

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
    /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *curr_mapping, *target_mapping = NULL;
  curr_mapping = nat->mappings;

  while (curr_mapping != NULL) {
    if (curr_mapping->type == type && curr_mapping->aux_int == aux_int && curr_mapping->ip_int == ip_int) {
      target_mapping = curr_mapping;
      break;
    }
    curr_mapping = curr_mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
 /* print_nat_mapping (target_mapping);*/
/*  assert (target_mapping != NULL);*/
  return target_mapping;
}

/* Get the connection associated with the given IP in the NAT entry. */
struct sr_nat_connection *sr_nat_lookup_connection (struct sr_nat_connection *curr_connection, uint32_t ip_connection) {
    while (curr_connection != NULL) {
        if (curr_connection->ip == ip_connection) {
            return curr_connection;
        }
       curr_connection = curr_connection->next;
    }

    return NULL;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *new_mapping = malloc(sizeof(struct sr_nat_mapping)); 

  new_mapping->type = type;
  new_mapping->last_updated = time(NULL);
  new_mapping->ip_int = ip_int;
  new_mapping->aux_int = aux_int;
  new_mapping->conns = NULL;
  new_mapping->prev = NULL;
  new_mapping->next = NULL; 
  struct sr_nat_mapping *curr_mapping = nat->mappings;
/*  nat->mappings = new_mapping;
  new_mapping->next = curr_mapping;*/
  assert (new_mapping != NULL);
  if (curr_mapping == NULL) {
	printf ("[NAT] inserting new mapping \n");
	nat->mappings = new_mapping; 
  } else {
	printf("[NAT] appending to mapping table \n");
        curr_mapping->prev = new_mapping; 
        new_mapping->next = curr_mapping;
        nat->mappings = new_mapping;
  }
  pthread_mutex_unlock(&(nat->lock));
  return new_mapping;
}

/* Generate a unique icmp identifier with o(n) complexity */
int sr_nat_generate_icmp_identifier(struct sr_nat *nat) {

    pthread_mutex_lock(&(nat->lock));

    uint16_t *free_icmp_identifiers = nat->free_icmp_identifiers;
    int i;

    for (i = MIN_ICMP_IDENTIFIER; i <= TOTAL_ICMP_IDENTIFIERS; i++) {
        if (free_icmp_identifiers[i] == 0) {
            free_icmp_identifiers[i] = 1;
            printf("Allocated ICMP identifier: %d\n", i);

            return i;
        }
    }

    pthread_mutex_unlock(&(nat->lock));
    return -1;
}

/* Generate a unique tcp identifier with o(n) complexity */
int sr_nat_generate_tcp_port(struct sr_nat *nat) {

    pthread_mutex_lock(&(nat->lock));

    uint16_t *free_tcp_ports = nat->free_tcp_ports;
    int i;

    for (i = MIN_TCP_PORT; i <= TOTAL_TCP_PORTS; i++) {
        if (free_tcp_ports[i] == 0) {
            free_tcp_ports[i] = 1;
            printf("Allocated TCP Port: %d\n", i);

            return i;
        }
    }

    pthread_mutex_unlock(&(nat->lock));
    return -1;
}

/* Insert a new connection associated with the given IP in the NAT entry. */
struct sr_nat_connection *sr_nat_insert_tcp_connection (struct sr_nat_mapping *mapping, uint32_t ip_connection) {
    struct sr_nat_connection *new_connection = malloc(sizeof(struct sr_nat_connection));
    assert(new_connection != NULL);
    memset(new_connection, 0, sizeof(struct sr_nat_connection));

    new_connection->last_updated = time(NULL);
    new_connection->ip = ip_connection;
    new_connection->tcp_state = CLOSED;

    struct sr_nat_connection *curr_connection = mapping->conns;

    mapping->conns = new_connection;
    new_connection->next = curr_connection;

    return new_connection;
}

/* Check to see if given interface is a NAT internal interface "eth1" */
int sr_nat_is_interface_internal(char *interface) {
  return strcmp(interface, NAT_INTERNAL_INTERFACE) == 0 ? 1 : 0;
}
