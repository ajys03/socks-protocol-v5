#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

int handle_method_negotiation(const int client_socket) {
    char buffer[BUFFER_SIZE];
    // maybe ssize_t -> https://stackoverflow.com/questions/131803/unsigned-int-vs-size-t
    // octect means 8 bits (1 byte) -> spec writes X'hh' (8 bits) to denote the value of the single octet
    int bytes_recv = recv(client_socket, buffer, 2, 0); // recv 2 bytes for ver & nmethods
    
    // protocol verion 5
    if (bytes_recv != 2 || buffer[0] == 0x05) {
        std::cerr << "Invalid SOCKS version or number of methods" << std::endl;
        close(client_socket);
        return;
    }

    int n_methods = static_cast<int>(buffer[1]);
    // Read the methods
    bytes_recv = recv(client_socket, buffer, n_methods, 0);
    if (bytes_recv != n_methods) {
        std::cerr << "Error reading methods" << std::endl;
        close(client_socket);
        return;
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
    return 0;
}

int main() {
    std::cout << "Starting Application..." << std::endl;

    // CREATE SOCKET
    int server_fd = socket(AF_INET, SOCK_STREAM, 0); // AF_INET -> Domain & SOCK_STREAM -> TCP
    if (server_fd < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // BIND SOCKET
    sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    // htons: host byte order -> network byte order
    servaddr.sin_port = htons(1080);
    // INADDR_ANY: listen on all available interfaces
    servaddr.sin_addr.s_addr = INADDR_ANY;

    // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int bind_success = bind(server_fd, reinterpret_cast<struct sockaddr*>(&servaddr), sizeof(servaddr));
    if (bind_success < 0) {
        std::cerr << "Error binding socket" << std::endl;
        close(server_fd);
        return -1;
    }

    // LISTEN SOCKET
    // int listen(int sockfd, int backlog);
    if (listen(server_fd, 5) < 0) {
        std::cerr << "Error listening on socket" << std::endl;
        close(server_fd);
        return -1;
    }

    std::cout << "SOCKS 5 proxy server listening on port 1080..." << std::endl;

    while (true) {
        sockaddr_in client_address{};
        socklen_t client_address_size = sizeof(client_address);
        int client_socket = accept(server_fd, reinterpret_cast<struct sockaddr*>(&client_address), &client_address_size);

        if (client_socket < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        std::cout << "Accepted connection from " << inet_ntoa(client_address.sin_addr) << std::endl;

        int neg_success = handle_method_negotiation(client_socket);
        if (neg_success < 0) {
            std::cerr << "Error negotiating methods" << std::endl;
            close(server_fd);
            return -1;
        }

        // REQUESTS
        
    }

    close(server_fd);

    return 0;
}