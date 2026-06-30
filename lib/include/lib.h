#pragma once

#include <cstdint>
#include "utils.h"
#include <arpa/inet.h>
#include "protocol.h"

/* Maximum segment size, change as you see fit */
#define MAX_DATA_SIZE 1024
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_data_hdr))

#define MAX_CONNECTIONS 32

/* Protocol control block. Used track different parameters about a connection. 
 * Will need to be extenden to solve the homework with other parameters such as
 * last_ack or status depending on how you implement your protocol. */
struct connection {
    /* common window for both the sender and receiver. */
    /* list window: A window representation */
    int sockfd; /* socket used for this connection */
    int conn_id; /* connection identifier */
    struct sockaddr_in servaddr; /* used to identify the destination */
    pthread_mutex_t con_lock; /* Used for syncronization with the handler thread and read/send calls.*/

    /* TODO. Parameters used only by the sender */
    int max_window_seq; /* Used to store the max number of packets that can be inflight, since we can
                           have many more packets in our window */
    pthread_cond_t wakeup_sender;

    uint16_t base_sender, next_sender, recv_sender_window;

    char sender_buffer[1048576]; // 1048576 = 1024 x 1024
    int sender_R_idx, sender_WR_idx, sender_used_for_buffer;

    char sender_win_buffer[1024][MAX_SEGMENT_SIZE];
    int sender_win_buffer_length[1024];
    bool sender_win_ack[1024];
    /* TODO. Parameters used only by the receiver */
    pthread_cond_t wakeup_recv;

    uint16_t recv_win;
    int recv_win_length, recv_win_buffer_length[1024];
    bool cons_recv_packets[1024];
    char recv_win_buffer[1024][MAX_SEGMENT_SIZE], recv_buffer[500000];

    int R_idx, WR_idx, bytes_remaining;
};

/* ########## API that we expose to the application ########### */

/* Equivalent of listen. Ran by the server to waits for a connection from a
 * client. Returns a connection id. Blocking untill it receives a connection
 * request */
int wait4connect(uint32_t ip, uint16_t port);
/* Equivalent of connect. Used by the client to connect to a server. */
int setup_connection(uint32_t ip, uint16_t port);
/* Equivalent to recv. Blocking if there is no data to be written in buffer */
int recv_data(int connectionid, char *buffer, int len);
/* Equivalent to send. Used by the client to send a stream of bytes as segments */
int send_data(int conn_id, char *buffer, int len);
/* Used to initialize your protocol on the receiver side. */
void init_receiver(int recv_buffer_bytes);
/* Used to initialize your protocol on the sender side */
void init_sender(int speed, int delay);

/* ######### Internal API used by sender and receiver ########### */
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);