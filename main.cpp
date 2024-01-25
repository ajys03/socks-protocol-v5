#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

    

}