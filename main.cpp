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

void send_reply(const int client_socket, uint8_t reply_type, int addr_type) {
    if (addr_type == 0x01) {
        char data_to_send[10] = {
                SOCKS5VER,0x00,RESERVED,0x01,
                BND_ADDR_IPV4[0],BND_ADDR_IPV4[1],BND_ADDR_IPV4[2],
                BND_ADDR_IPV4[3], BND_PORT[0], BND_PORT[1]
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

void connect_req(const int client_socket, const int addr_type) {
    int host_socket;
    if (addr_type == 0x01) {
        host_socket = handle_ipv4(client_socket);
    } else if (addr_type == 0x03) {
        // DOMAIN NAME
        host_socket = -1;
    } else if (addr_type == 0x04) {
        // IPv6
        host_socket = -1;
    } else {
        host_socket = -1;
    }

    if (host_socket == -1) {
        std::cerr << "Error connecting to dest address" << std::endl;
    }

    char buffer[BUFFER_SIZE];
    ssize_t count;

    while(true){
        std::cout << "cycle" << "\n";
        // recv data from client_socket
        count = recv(client_socket, buffer, sizeof(buffer), 0);
        if(count > 0 ){
            count = send(host_socket, buffer, count, 0);
            // maybe error handle
        }
        // recv data from the host_socket
        count = recv(host_socket, buffer, sizeof(buffer), 0);
        if(count > 0 ) {
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