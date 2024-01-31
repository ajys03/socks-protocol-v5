#include <iostream>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

void send_reply(const int client_socket, char reply_type, int addr_type) {
    if (addr_type == 0x01) {
        char data_to_send[10] = {
                SOCKS5VER,0x00,RESERVED,0x01,
                BND_ADDR_IPV4[0],BND_ADDR_IPV4[1],BND_ADDR_IPV4[2],
                BND_ADDR_IPV4[3], BND_PORT[0], BND_PORT[1]
        };
        send(client_socket, data_to_send, sizeof(data_to_send), 0);
    }
}

int proxy_ipv4(const int client_socket, const char* dest_addr, const char* dest_port) {
    int dest_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        std::cerr << "Error creating socket for proxy" << std::endl;
        close(dest_socket);
        close(client_socket);
        return -1;
    }

    sockaddr_in dest_address;
    dest_address.sin_family = AF_INET;
    dest_address.sin_port = htons(std::stoi(dest_port));

    if (inet_pton(AF_INET, dest_addr, &dest_address.sin_addr) <= 0) {
        std::cerr << "Error converting server address" << std::endl;
        close(dest_socket);
        close(client_socket);
        return -1;
    }

    if (connect(client_socket, (struct sockaddr *)&dest_address, sizeof(dest_address)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        close(dest_socket);
        close(client_socket);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t client_reply = 0;
    while ((client_reply = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        buffer[client_reply] = '\0';

        // Relay data from client_socket to dest_socket
        send(dest_socket, buffer, client_reply, 0);

        // Receive data from dest_socket and relay it back to client_socket
        int dest_bytes_received = recv(dest_socket, buffer, sizeof(buffer), 0);
        if (dest_bytes_received > 0) {
            buffer[dest_bytes_received] = '\0';
            send(client_socket, buffer, dest_bytes_received, 0);
        }
    }

    return 0;
}

void handle_ipv4(const int client_socket) {
    char reply_type = 0x00;
    char ipv4_addr[4];
    ssize_t reply = recv(client_socket, ipv4_addr, 4, 0);
    if (reply != 4) {
        std::cerr << "Error reading IPv4 address" << std::endl;
        reply_type = 0x01;
    }
    char port[2];
    ssize_t reply0 = recv(client_socket, port, 2, 0);
    if (reply0 != 2) {
        std::cerr << "Error reading IPv4 address's port" << std::endl;
        reply_type = 0x01;
    }

    if (proxy_ipv4(client_socket, ipv4_addr, port) == -1) {
        reply_type = 0x01;
    }

    send_reply(client_socket, reply_type, 0x01);
}

void connect_req(const int client_socket, const int addr_type) {
    if (addr_type == 0x01) {
        handle_ipv4(client_socket);
    }

}

void handle_socks_request(const int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_socket, buffer, 4, 0);
    if (bytes_received != 4 || buffer[0] != SOCKS5VER) {
        std::cerr << "Invalid SOCKS version or request" << std::endl;
        close(client_socket);
        return;
    }

    int cmd = static_cast<int>(static_cast<unsigned char>(buffer[1]));
    int addr_type = static_cast<int>(static_cast<unsigned char>(buffer[3]));

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
    sockaddr_in servaddr;
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
        sockaddr_in client_address;
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