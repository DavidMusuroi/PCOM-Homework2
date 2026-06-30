#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
using namespace std;

map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0, get_max_win_seq = 64;

int send_data(int conn_id, char *buffer, int len)
{

    pthread_mutex_lock(&cons[conn_id]->con_lock);

    /* We will write code here as to not have sync problems with sender_handler */

    auto connection = cons[conn_id];

    if(connection->sender_used_for_buffer + len > 1048576){ // 1048576 = 1024 x 1024
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        return -1;
    }
    else{
        for(int i = 0; i < len; i++){
            connection->sender_buffer[connection->sender_WR_idx] = buffer[i];
            connection->sender_WR_idx++;
            connection->sender_WR_idx %= 1048576;
        }

    connection->sender_used_for_buffer += len;
    pthread_cond_signal(&connection->wakeup_sender);

    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return len;
    }
}

void try_to_send_some_new_segments(struct connection* con){
    while(1){
        int get_win_limit = con->max_window_seq;
        if((int)con->recv_sender_window < get_win_limit){
            get_win_limit = (int)con->recv_sender_window;
        }
        if(con->next_sender - con->base_sender >= get_win_limit || con->sender_used_for_buffer == 0){
            break;
        }
        char segment[MAX_SEGMENT_SIZE];
        struct poli_tcp_data_hdr *header = (struct poli_tcp_data_hdr*)segment;
        uint16_t find_payload_length = 1024;
        if(con->sender_used_for_buffer < 1024){
            find_payload_length = con->sender_used_for_buffer;
        }

        header->protocol_id = 42;
        header->conn_id = (uint8_t) con->conn_id;
        header->type = 0;
        header->seq_num = htons((uint16_t)con->next_sender);
        header->len = htons(find_payload_length);
        
        char *payload = segment + sizeof(struct poli_tcp_data_hdr);
        for(int i = 0; i < find_payload_length; i++){
            payload[i] = con->sender_buffer[con->sender_R_idx];
            con->sender_R_idx++;
            con->sender_R_idx %= 1048576; // 1048576 = 1024 x 1024
        }
        con->sender_used_for_buffer -= find_payload_length;

        int packet = con->next_sender % 1024;
        memcpy(con->sender_win_buffer[packet], segment, sizeof(struct poli_tcp_data_hdr) + find_payload_length);
        con->sender_win_buffer_length[packet] = sizeof(struct poli_tcp_data_hdr) + find_payload_length;
        con->sender_win_ack[packet] = false;
        sendto(con->sockfd, segment, sizeof(struct poli_tcp_data_hdr) + find_payload_length, 0, (struct sockaddr*)&con->servaddr, sizeof(con->servaddr));
        con->next_sender++;
    }
}

void *sender_handler(void *arg)
{
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {

        if (cons.size() == 0) {
            continue;
        }
        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
            if(res == -14){
                for(auto [id, con] : cons){
                    pthread_mutex_lock(&con->con_lock);
                    try_to_send_some_new_segments(con);
                    pthread_mutex_unlock(&con->con_lock);
                }
            }
        } while(res == -14 || conn_id == -1);

        if(cons.count(conn_id) == 0){
            continue;
        }

        pthread_mutex_lock(&cons[conn_id]->con_lock);

        auto con = cons[conn_id];
        if(res == -1){
            for(uint16_t sequence_nr = con->base_sender; sequence_nr < con->next_sender; sequence_nr++){
                int packet = sequence_nr % 1024;
                if(con->sender_win_ack[packet] == false && con->sender_win_buffer_length[packet] > 0){
                    sendto(con->sockfd, con->sender_win_buffer[packet], con->sender_win_buffer_length[packet], 0, (struct sockaddr*)&con->servaddr, sizeof(con->servaddr));
                }
            }
            pthread_mutex_unlock(&cons[conn_id]->con_lock);
            continue;
        }
        else{
            struct poli_tcp_ctrl_hdr *ctrl_header = (struct poli_tcp_ctrl_hdr*)buf;
            if(ctrl_header->type != 1){
                pthread_mutex_unlock(&cons[conn_id]->con_lock);
                continue;
            }
            else{
                uint16_t ack_nr = ntohs(ctrl_header->ack_num);
                con->recv_sender_window = ntohs(ctrl_header->recv_window);
                if(ack_nr > con->base_sender){
                    for(uint16_t sequence = con->base_sender; sequence < ack_nr; sequence++){
                        int pachet = sequence % 1024;
                        con->sender_win_ack[pachet] = true;
                        con->sender_win_buffer_length[pachet] = 0;
                    }
                    con->base_sender = ack_nr;
                }
                try_to_send_some_new_segments(con);
                pthread_mutex_unlock(&cons[conn_id]->con_lock);
            }
        }
        /* Handle segment received from the receiver. We use this between locks
        as to not have synchronization issues with the send_data calls which are
        on the main thread */
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    /* Implement the sender part of the Three Way Handshake. Blocks
    until the connection is established */

    char buffer[MAX_SEGMENT_SIZE];
    struct sockaddr_in address_of_server;


    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    memset(con, 0, sizeof(struct connection));
    int conn_id = 2, fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0){
        unsigned int get_random_value;
        read(fd, &get_random_value, sizeof(get_random_value));
        conn_id = (get_random_value % 255) + 2;
    }

    con->conn_id = conn_id;
    con->base_sender = con->next_sender = 0;
    con->recv_sender_window = 128;
    con->max_window_seq = get_max_win_seq;
    con->sender_used_for_buffer = con->sender_R_idx = con->sender_WR_idx = 0;
    memset(con->sender_win_ack, false, sizeof(con->sender_win_ack));
    memset(con->sender_win_buffer_length, 0, sizeof(con->sender_win_buffer_length));
    pthread_cond_init(&con->wakeup_sender, NULL);

    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&address_of_server, 0, sizeof(address_of_server));
    address_of_server.sin_family = AF_INET;
    address_of_server.sin_port = htons(8032);
    address_of_server.sin_addr.s_addr = ip;

    struct poli_tcp_ctrl_hdr syn_pachet;
    memset(&syn_pachet, 0, sizeof(syn_pachet));
    syn_pachet.protocol_id = 42;
    syn_pachet.conn_id = (uint8_t) conn_id;
    syn_pachet.type = 2;
    syn_pachet.ack_num = 0;
    syn_pachet.recv_window = htons(128);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sendto(con->sockfd, &syn_pachet, sizeof(syn_pachet), 0, (struct sockaddr*)&address_of_server, sizeof(address_of_server));
    while(1){
        struct sockaddr_in from_whcih_socket;
        socklen_t socket_length = sizeof(from_whcih_socket);
        int rc = recvfrom(con->sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&from_whcih_socket, &socket_length);
        if(rc < 0){
            sendto(con->sockfd, &syn_pachet, sizeof(syn_pachet), 0, (struct sockaddr*)&address_of_server, sizeof(address_of_server));
            continue;
        }
        struct poli_tcp_ctrl_hdr *ctrl_header = (struct poli_tcp_ctrl_hdr*)buffer;
        if(ctrl_header->type == 3){
            uint16_t my_port;
            memcpy(&my_port, buffer + sizeof(struct poli_tcp_ctrl_hdr), sizeof(uint16_t));
            address_of_server.sin_port = my_port;
            con->servaddr = address_of_server;
            break;
        }
    }


    /* // This can be used to set a timer on a socket 
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 100000;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("Error");
    } */

    /* We will send the SYN on 8031. Then we will receive a SYN-ACK with the connection
     * port. We can use con->sockfd for both cases, but we will need to update server_addr
     * with the port received via SYN-ACK */

    /* Since we can have multiple connection, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    tv.tv_sec = tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct poli_tcp_ctrl_hdr ack_pachet;
    memset(&ack_pachet, 0, sizeof(ack_pachet));
    ack_pachet.protocol_id = 42;
    ack_pachet.conn_id = (uint8_t) conn_id;
    ack_pachet.type = 1;
    ack_pachet.ack_num = 0;
    ack_pachet.recv_window = htons(128);
    sendto(con->sockfd, &ack_pachet, sizeof(ack_pachet), 0, (struct sockaddr*)&con->servaddr, sizeof(con->servaddr));

    data_fds[fdmax].fd = con->sockfd;    
    data_fds[fdmax].events = POLLIN;    
    
    /* This creates a timer and sets it to trigger every 1 sec. We use this
       to know if a timeout has happend on our connection */
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME,  0);    
    timer_fds[fdmax].events = POLLIN;    
    struct itimerspec spec;     
    spec.it_value.tv_sec = 0;    
    spec.it_value.tv_nsec = 50000000;    
    spec.it_interval.tv_sec = 0;    
    spec.it_interval.tv_nsec = 50000000;    
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);    
    fdmax++;


    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    DEBUG_PRINT("Connection established!");

    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret, get_segm;

    /* Create a thread that will*/
    get_segm = (speed * delay * 500) / MAX_DATA_SIZE;
    if(get_segm < 1){
        get_segm = 1;
    }
    if(get_segm > 1024){
        get_segm = 1024;
    }
    get_max_win_seq = get_segm;
    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
