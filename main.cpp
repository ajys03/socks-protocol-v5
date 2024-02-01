#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef unsigned __int128 uint128_t;

const int BUFFER_SIZE = 4096;
const int SOCKS5VER = 0x05;
const int RESERVED = 0x00;
const char BND_ADDR_IPV4[4] = {0, 0, 0, 0};
const char BND_ADDR_IPV6[16] = {0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0};
const char BND_PORT[2] = {0,0};

int handle_method_negotiation(const int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t reply = recv(client_socket, buffer, 2, 0);
    
    if (reply != 2 || buffer[0] != SOCKS5VER) {
        std::cerr << "Invalid SOCKS version or number of methods" << std::endl;
        close(client_socket);
        return -1;
    }

    int n_methods = static_cast<int>(static_cast<unsigned char>(buffer[1]));
    reply = recv(client_socket, buffer, n_methods, 0);
    if (reply != n_methods) {
        std::cerr << "Error reading methods" << std::endl;
        close(client_socket);
        return -1;
    }

    // Use 'NO AUTHENTICATION REQUIRED' (X'00') but first check if it is supported
    int i = 0;
    while (buffer[i] != 0x00) {
        if (i == n_methods - 1) {
            send(client_socket, "\x05\xff", 2, 0);
            close(client_socket);
            return -1;
        }
        i++;
    }

    // Send the selected method (X'00' for 'NO AUTHENTICATION REQUIRED')
    send(client_socket, "\x05\x00", 2, 0);

    std::cout << "Complete Method Handshake" << std::endl;
    return 0;
}

void send_reply(const int client_socket, uint8_t reply_type, int addr_type) {
    // TODO: use reply_type
    if (addr_type == 0x01) {
        char data_to_send[10] = {
                SOCKS5VER,0x00,RESERVED,0x01,
                BND_ADDR_IPV4[0],BND_ADDR_IPV4[1],BND_ADDR_IPV4[2],
                BND_ADDR_IPV4[3], BND_PORT[0], BND_PORT[1]
        };
        send(client_socket, data_to_send, sizeof(data_to_send), 0);
    } else if (addr_type == 0x03) {
        char data_to_send[10] = {
                SOCKS5VER,0x00,RESERVED,0x03,
                BND_ADDR_IPV4[0],BND_ADDR_IPV4[1],BND_ADDR_IPV4[2],
                BND_ADDR_IPV4[3], BND_PORT[0], BND_PORT[1]
        };
        send(client_socket, data_to_send, sizeof(data_to_send), 0);
    } else {
        char data_to_send[22] = {
                SOCKS5VER,0x00,RESERVED,0x04,
                BND_ADDR_IPV6[0],BND_ADDR_IPV6[1],BND_ADDR_IPV6[2],
                BND_ADDR_IPV6[3], BND_ADDR_IPV6[4],BND_ADDR_IPV6[5],BND_ADDR_IPV6[6],
                BND_ADDR_IPV6[7],BND_ADDR_IPV6[8],BND_ADDR_IPV6[9],BND_ADDR_IPV6[10],
                BND_ADDR_IPV6[11],BND_ADDR_IPV6[12],BND_ADDR_IPV6[13],BND_ADDR_IPV6[14],
                BND_ADDR_IPV6[15],BND_PORT[0], BND_PORT[1]
        };
        send(client_socket, data_to_send, sizeof(data_to_send), 0);
    }
}

int handle_ipv4(const int client_socket) {
    uint8_t reply_type = 0x00;

    uint8_t ipv4_addr[4];
    ssize_t reply = recv(client_socket, ipv4_addr, 4, 0);

    if (reply != 4) {
        std::cerr << "Error reading IPv4 address" << std::endl;
        reply_type = 0x01;
    }

    uint32_t ip_address =(ipv4_addr[0] << 24) | (ipv4_addr[1] << 16) | (ipv4_addr[2] << 8) | ipv4_addr[3];

    uint8_t port[2];
    reply = recv(client_socket, port, 2, 0);
    if (reply != 2) {
        std::cerr << "Error reading IPv4 address's port" << std::endl;
        reply_type = 0x01;
    }

    uint16_t port_number = (port[0] << 8) | port[1];

    int dest_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        std::cerr << "Error creating socket for proxy" << std::endl;
        reply_type = 0x01;
    }

    sockaddr_in dest_address = {};
    dest_address.sin_family = AF_INET;
    dest_address.sin_port = htons(port_number);
    dest_address.sin_addr.s_addr = ip_address;

    if (connect(dest_socket, (struct sockaddr *)&dest_address, sizeof(dest_address)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        close(dest_socket);
        close(client_socket);
        return -1;
    }

    send_reply(client_socket, reply_type, 0x01);

    return dest_socket;
}

int handle_dname(const int client_socket) {
    uint8_t reply_type = 0x00;

    uint8_t len;
    ssize_t reply = recv(client_socket, &len, 1, 0);
    if (reply != 1) {
        std::cerr << "Error reading domain name address's length" << std::endl;
        reply_type = 0x01;
    }

    char domain_name[len + 1];
    reply = recv(client_socket, domain_name, len, 0);
    if (reply != len) {
        std::cerr << "Error reading domain name address" << std::endl;
        reply_type = 0x01;
    }
    domain_name[len] = '\0';

    uint8_t port[2];
    reply = recv(client_socket, port, 2, 0);
    if (reply != 2) {
        std::cerr << "Error reading IPv4 address's port" << std::endl;
        reply_type = 0x01;
    }

    uint16_t port_number = (port[0] << 8) | port[1];

    std::string port_str = std::to_string(port_number);
    const char* port_char = port_str.c_str();

    int dest_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        std::cerr << "Error creating socket for proxy" << std::endl;
        reply_type = 0x01;
    }

    struct addrinfo hints = {}, *serverInfo;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain_name, port_char, &hints, &serverInfo) != 0) {
        std::cerr << "Error getting server address" << std::endl;
        reply_type = 0x01;
    }

    if (connect(dest_socket, serverInfo->ai_addr, serverInfo->ai_addrlen) == -1) {
        std::cerr << "Error connecting to the server" << std::endl;
        close(dest_socket);
        close(client_socket);
        freeaddrinfo(serverInfo);
        reply_type = 0x01;
    }

    send_reply(client_socket, reply_type, 0x03);

    return dest_socket;
}

int handle_ipv6(const int client_socket) {
    uint8_t reply_type = 0x00;

    uint8_t ipv6_addr[16];
    ssize_t reply = recv(client_socket, ipv6_addr, 16, 0);

    if (reply != 16) {
        std::cerr << "Error reading IPv6 address" << std::endl;
        reply_type = 0x01;
    }

    uint128_t ip_address = 0;
    for (uint8_t byte : ipv6_addr) {
        ip_address = (ip_address << 8) | byte;
    }

    uint8_t port[2];
    reply = recv(client_socket, port, 2, 0);
    if (reply != 2) {
        std::cerr << "Error reading IPv4 address's port" << std::endl;
        reply_type = 0x01;
    }

    uint16_t port_number = (port[0] << 8) | port[1];

    int dest_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        std::cerr << "Error creating socket for proxy" << std::endl;
        reply_type = 0x01;
    }

    sockaddr_in6 dest_address = {};
    dest_address.sin6_family = AF_INET6;
    dest_address.sin6_port = htons(port_number);
    memcpy(&(dest_address.sin6_addr), &ip_address, sizeof(ip_address));

    if (connect(dest_socket, (struct sockaddr *)&dest_address, sizeof(dest_address)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        close(dest_socket);
        close(client_socket);
        return -1;
    }

    send_reply(client_socket, reply_type, 0x04);

    return dest_socket;
}

void connect_req(const int client_socket, const int addr_type) {
    int host_socket;
    if (addr_type == 0x01) {
        host_socket = handle_ipv4(client_socket);
    } else if (addr_type == 0x03) {
        host_socket = handle_dname(client_socket);
    } else if (addr_type == 0x04) {
        host_socket = handle_ipv6(client_socket);
    } else {
        host_socket = -1;
    }

    if (host_socket <= -1) {
        std::cerr << "Error connecting to dest address" << std::endl;
    }

    char buffer[BUFFER_SIZE];
    ssize_t count;

    while(true){
        std::cout << "cycle" << "\n";
        count = recv(client_socket, buffer, sizeof(buffer), 0);
        if(count > 0){
            count = send(host_socket, buffer, count, 0);
            // maybe error handle
        }
        count = recv(host_socket, buffer, sizeof(buffer), 0);
        if(count > 0) {
            count = send(client_socket, buffer, count, 0);
        }
    }
}

void handle_socks_request(const int client_socket) {
    uint8_t buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_socket, buffer, 4, 0);
    if (bytes_received != 4 || buffer[0] != SOCKS5VER) {
        std::cerr << "Invalid SOCKS version or request" << std::endl;
        close(client_socket);
        return;
    }

    uint8_t cmd = buffer[1];
    uint8_t addr_type = buffer[3];

    if (cmd == 0x01) {
        std::cout << "Received SOCKS CONNECT request." << std::endl;
        connect_req(client_socket, addr_type);
    }

}

int main() {
    std::cout << "Starting Application..." << std::endl;

    // CREATE SOCKET
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // BIND SOCKET
    sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1080);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    int bind_success = bind(server_fd, reinterpret_cast<struct sockaddr*>(&servaddr), sizeof(servaddr));
    if (bind_success < 0) {
        std::cerr << "Error binding socket" << std::endl;
        close(server_fd);
        return -1;
    }

    // LISTEN SOCKET
    if (listen(server_fd, 5) < 0) {
        std::cerr << "Error listening on socket" << std::endl;
        close(server_fd);
        return -1;
    }

    std::cout << "SOCKS 5 proxy server listening on port 1080..." << std::endl;

    while (true) {
        sockaddr_in client_address = {};
        socklen_t client_address_size = sizeof(client_address);
        int client_socket = accept(server_fd, reinterpret_cast<struct sockaddr*>(&client_address), &client_address_size);

        if (client_socket < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }
        
        std::cout << "Accepted connection from " << inet_ntoa(client_address.sin_addr) << std::endl;

        // HANDLE METHOD NEGOTIATION
        int neg_success = handle_method_negotiation(client_socket);
        if (neg_success < 0) {
            std::cerr << "Error negotiating methods" << std::endl;
            close(client_socket);
            close(server_fd);
            return -1;
        }

        // REQUESTS + REPLIES
        handle_socks_request(client_socket);

        std::cout << "Completed SOCKS 5" << std::endl;
    }

}