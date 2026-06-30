#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
#include <sys/timerfd.h>
#include <cstring>

using namespace std;

map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0, sockfd = -1;

int recv_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);
    
    /* We will write code here as to not have sync problems with recv_handler */

    auto connection = cons[conn_id];
    while(connection->bytes_remaining == 0){
        pthread_cond_wait(&connection->wakeup_recv, &connection->con_lock);
    }

    if(len <= connection->bytes_remaining){
        size = len;
    }
    else{
        size = connection->bytes_remaining;
    }

    for(int i = 0; i < size; i++){
        buffer[i] = connection->recv_buffer[connection->R_idx];
        connection->R_idx++;
        connection->R_idx %= 500000;
    }

    connection->bytes_remaining -= size;

    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return size;
}

void send_ack(struct connection* connection, int protocol_id, int conn_id, uint16_t ack_num, uint16_t recv_window_len){
    struct poli_tcp_ctrl_hdr ack_header;
    memset(&ack_header, 0, sizeof(ack_header));
    ack_header.protocol_id = protocol_id;
    ack_header.conn_id = conn_id;
    ack_header.type = 1;
    ack_header.ack_num = htons(ack_num);
    ack_header.recv_window = htons(recv_window_len);
    sendto(connection->sockfd, &ack_header, sizeof(ack_header), 0, (struct sockaddr*)&connection->servaddr, sizeof(connection->servaddr));
}

void *receiver_handler(void *arg)
{

    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("Starting recviver handler\n");

    while (1) {

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14 || conn_id == -1);

        if(cons.count(conn_id) == 0){
            continue;
        }

        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received from the sender. We use this between locks
        as to not have synchronization issues with the recv_data calls which are
        on the main thread */

        auto connection = cons[conn_id];
        uint16_t real_recv_win;
        if((500000 - connection->bytes_remaining) <= 131072){ // 1024 x 128
            real_recv_win = (500000 - connection->bytes_remaining) / 1024;
        }
        else{
            real_recv_win = 128;
        }
        if(res == -1){
            send_ack(connection, 42, conn_id, connection->recv_win, real_recv_win);
            pthread_mutex_unlock(&cons[conn_id]->con_lock);
            continue;
        }
        else{
            struct poli_tcp_data_hdr *header = (poli_tcp_data_hdr*) segment;
            if(header->type != 0){
                pthread_mutex_unlock(&cons[conn_id]->con_lock);
                continue;
            }
            else{
                char *get_payload = segment + sizeof(struct poli_tcp_data_hdr);
                if(ntohs(header->seq_num) < connection->recv_win){
                    send_ack(connection, header->protocol_id, header->conn_id, connection->recv_win, real_recv_win);
                    pthread_mutex_unlock(&cons[conn_id]->con_lock);
                    continue;
                }
                else if(ntohs(header->seq_num) < connection->recv_win + connection->recv_win_length){
                    int nr = ntohs(header->seq_num) % 1024;
                    if(connection->cons_recv_packets[nr] == false){
                        connection->cons_recv_packets[nr] = true;
                        connection->recv_win_buffer_length[nr] = ntohs(header->len);
                        memcpy(connection->recv_win_buffer[nr], get_payload, ntohs(header->len));
                    }
                    int crt_packet = connection->recv_win % 1024;
                    while(connection->cons_recv_packets[crt_packet] != 0){
                        uint16_t length = connection->recv_win_buffer_length[crt_packet];

                        if(length > 500000 - connection->bytes_remaining){
                            break;
                        }
                        for(int i = 0; i < length; i++){
                            connection->recv_buffer[connection->WR_idx] = connection->recv_win_buffer[crt_packet][i];
                            connection->WR_idx++;
                            connection->WR_idx %= 500000;
                        }
                        connection->bytes_remaining += length;
                        connection->cons_recv_packets[crt_packet] = false;
                        connection->recv_win_buffer_length[crt_packet] = 0;
                        connection->recv_win++;
                        crt_packet = connection->recv_win % 1024;
                    }
                    pthread_cond_signal(&connection->wakeup_recv);
                    if((500000 - connection->bytes_remaining) <= 131072){ // 1024 x 128
                        real_recv_win = (500000 - connection->bytes_remaining) / 1024;
                    }
                    else{
                        real_recv_win = 128;
                    }
                    send_ack(connection, header->protocol_id, header->conn_id, connection->recv_win, real_recv_win);
                    pthread_mutex_unlock(&cons[conn_id]->con_lock);
                }
                else{
                    pthread_mutex_unlock(&cons[conn_id]->con_lock);
                }
            }
        }
    }

    
}

int wait4connect(uint32_t ip, uint16_t port)
{
    /* TODO: Implement the Three Way Handshake on the receiver part. This blocks
     * until a connection is established. */

    char buffer[MAX_SEGMENT_SIZE];
    struct sockaddr_in address_of_client;
    socklen_t address_length = sizeof(address_of_client);


    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    memset(con, 0, sizeof(struct connection));
    con->recv_win_length = 128;
    con->recv_win = con->R_idx = con->WR_idx = con->bytes_remaining = 0;
    memset(con->cons_recv_packets, false, sizeof(con->cons_recv_packets));
    pthread_cond_init(&con->wakeup_recv, NULL);


    /* This can be used to set a timer on a socket, useful once we received a
     * SYN. You may want to disable by setting the time to 0 (tv_sec = 0,
     * tv_usec = 0)
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 100000;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("Error");
    } */

    /* Receive SYN on the connection socket. Create a new socket and bind it to
     * the chosen port. Send the data port number via SYN-ACK to the client */

    struct poli_tcp_ctrl_hdr *ctrl_header;
    do{
        recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&address_of_client, &address_length);
        ctrl_header = (struct poli_tcp_ctrl_hdr*) buffer;
    } while(ctrl_header->type != 2);

    int conn_id = ctrl_header->conn_id;
    con->conn_id = ctrl_header->conn_id;
    con->servaddr = address_of_client;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in address_of_server;
    socklen_t server_adress_length = sizeof(address_of_server);
    memset(&address_of_server, 0, sizeof(address_of_server));
    address_of_server.sin_family = AF_INET;
    address_of_server.sin_port = 0;
    address_of_server.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(con->sockfd, (struct sockaddr*)&address_of_server, sizeof(address_of_server));
    getsockname(con->sockfd, (struct sockaddr*)&address_of_server, &server_adress_length);

    char syn_ack_buffer[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)];
    memset(syn_ack_buffer, 0, sizeof(syn_ack_buffer));

    struct poli_tcp_ctrl_hdr *send_syn_ack = (struct poli_tcp_ctrl_hdr*)syn_ack_buffer;
    send_syn_ack->protocol_id = 42;
    send_syn_ack->conn_id = (uint8_t) conn_id;
    send_syn_ack->type = 3;
    send_syn_ack->ack_num = 0;
    send_syn_ack->recv_window = htons(128);
    memcpy(syn_ack_buffer + sizeof(struct poli_tcp_ctrl_hdr), &address_of_server.sin_port, sizeof(uint16_t));

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sendto(sockfd, syn_ack_buffer, sizeof(syn_ack_buffer), 0, (struct sockaddr*)&address_of_client, sizeof(address_of_client));
    while(1){
        struct sockaddr_in from_whcih_socket;
        socklen_t socket_length = sizeof(from_whcih_socket);
        int rc = recvfrom(con->sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&from_whcih_socket, &socket_length);
        if(rc < 0){
            sendto(sockfd, syn_ack_buffer, sizeof(syn_ack_buffer), 0, (struct sockaddr*)&address_of_client, sizeof(address_of_client));
            continue;
        }
        ctrl_header = (struct poli_tcp_ctrl_hdr*)buffer;
        if(ctrl_header->type == 1){
            con->servaddr = from_whcih_socket;
            break;
        }
    }
    tv.tv_sec = tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    /* Since we can have multiple connection, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    data_fds[fdmax].fd = con->sockfd;    
    data_fds[fdmax].events = POLLIN;    
    
    /* This creates a timer and sets it to trigger every 1 sec. We use this
       to know if a timeout has happend on a connection */
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

    return con->conn_id;
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;

    /* TODO: Create the connection socket and bind it to 8031 */

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in my_new_addr;
    memset(&my_new_addr, 0, sizeof(my_new_addr));
    my_new_addr.sin_family = AF_INET;
    my_new_addr.sin_port = htons(8032);
    my_new_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recv_buffer_bytes, sizeof(int));
    // ret = 
    bind(sockfd, (struct sockaddr*)&my_new_addr, sizeof(my_new_addr));

    ret = pthread_create( &thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}
