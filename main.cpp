#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096
const uint8_t SOCKS5VER = 0x05;
const uint8_t RESERVED = 0x00;

// std::string domain_to_ipv4(std::string domain_name) {
//     // Convert the domain name to an IP address.
//     struct sockaddr_in addr;
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(80); // Port 80 is the default HTTP port.
//     addr.sin_addr.s_addr = inet_addr(domain_name.c_str());

//     // Check if the IP address is valid.
//     if (addr.sin_addr.s_addr == INADDR_NONE) {
//         std::cerr << "Invalid domain name." << std::endl;
//         return "error";
//     }

//     // Print the IP address to the console.
//     std::cout << "The IP address for " << domain_name << " is " << inet_ntoa(addr.sin_addr) << std::endl;

//     return inet_ntoa(addr.sin_addr);
// }

int handle_method_negotiation(const int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_recv = recv(client_socket, buffer, 2, 0);
    
    if (bytes_recv != 2 || buffer[0] != SOCKS5VER) {
        std::cerr << "Invalid SOCKS version or number of methods" << std::endl;
        close(client_socket);
        return -1;
    }

    int n_methods = static_cast<int>(buffer[1]);
    bytes_recv = recv(client_socket, buffer, n_methods, 0);
    if (bytes_recv != n_methods) {
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

void bidirec_traffic(int client_socket, int tcp_client) {
    fd_set fds;
    char buffer[BUFFER_SIZE];
    int bytesRead;

    while (true) {
        FD_ZERO(&fds);
        FD_SET(client_socket, &fds);
        FD_SET(tcp_client, &fds);

        // Wait for activity on either socket
        if (select(std::max(client_socket, tcp_client) + 1, &fds, nullptr, nullptr, nullptr) < 0) {
            std::cerr << "Error in select" << std::endl;
            break;
        }

        // Forward data from local to remote
        if (FD_ISSET(client_socket, &fds)) {
            bytesRead = recv(client_socket, buffer, BUFFER_SIZE, 0);
            if (bytesRead <= 0) {
                break;
            }
            send(tcp_client, buffer, bytesRead, 0);
        }

        // Forward data from remote to local
        if (FD_ISSET(tcp_client, &fds)) {
            bytesRead = recv(tcp_client, buffer, BUFFER_SIZE, 0);
            if (bytesRead <= 0) {
                break;
            }
            send(client_socket, buffer, bytesRead, 0);
        }
    }
}


void tcp_client(int client_socket, std::string address, unsigned short port) {
    int tcp_client = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_client < 0) {
        std::cerr << "Error creating local socket" << std::endl;
        return;
    }

    sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(0); // let system choose available port
    servaddr.sin_addr.s_addr = INADDR_ANY;

    int bind_success = bind(tcp_client, reinterpret_cast<struct sockaddr*>(&servaddr), sizeof(servaddr));
    if (bind_success < 0) {
        std::cerr << "Error binding server's client socket" << std::endl;
        close(tcp_client);
        return;
    }

    sockaddr_in remote_server;
    remote_server.sin_family = AF_INET;
    remote_server.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &(remote_server.sin_addr));

    if (connect(tcp_client, reinterpret_cast<struct sockaddr*>(&remote_server), sizeof(remote_server)) == -1) {
        std::cerr << "Error binding to target server as client socket" << std::endl;
        close(tcp_client);
        return;
    }
    std::cout << "Connected to " << address << ":" << port << " from local port " << ntohs(servaddr.sin_port) << std::endl;

    bidirec_traffic(client_socket, tcp_client); // Forward user input to the server
    close(tcp_client);

    return;
}

std::string get_atyp_info(int atyp, int client_socket) {
    // Determine address type based on ATYP
    int bytes_received = 0;
    if (atyp == 0x01) {
        // IPv4 address
        char ipv4_addr[4];
        bytes_received = recv(client_socket, ipv4_addr, 4, 0);
        if (bytes_received != 4) {
            std::cerr << "Error reading IPv4 address" << std::endl;
            close(client_socket);
            return "e";
        }
        return ipv4_addr;
    } else if (atyp == 0x03) {
        // Domain name
        char domain_length[1];
        bytes_received = recv(client_socket, domain_length, 1, 0);
        if (bytes_received != 1) {
            std::cerr << "Error reading domain length" << std::endl;
            close(client_socket);
            return "e";
        }
        int domain_length_int = static_cast<int>(domain_length[0]);
        char domain_name[256];
        bytes_received = recv(client_socket, domain_name, domain_length_int, 0);
        if (bytes_received != domain_length_int) {
            std::cerr << "Error reading domain name" << std::endl;
            close(client_socket);
            return "e";
        }
        // does not come with null terminating
        domain_name[domain_length_int] = '\0';
        // std::string domain_name_ipv4 = domain_to_ipv4(domain_name);
        return domain_name;
    } else if (atyp == 0x04) {
        // IPv6 address
        char ipv6_addr[6];
        bytes_received = recv(client_socket, ipv6_addr, 6, 0);
        if (bytes_received != 6) {
            std::cerr << "Error reading IPv4 address" << std::endl;
            close(client_socket);
            return "e";
        }
        return ipv6_addr;
    } else {
        std::cerr << "ATYP does not exist" << std::endl;
        close(client_socket);
        return "e";
    }
}

void handle_socks_request(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, 4, 0);
    if (bytes_received != 4 || buffer[0] != SOCKS5VER) {
        std::cerr << "Invalid SOCKS version or request" << std::endl;
        close(client_socket);
        return;
    }

    int cmd = static_cast<int>(buffer[1]);
    int rsv = static_cast<int>(buffer[2]);
    int atyp = static_cast<int>(buffer[3]);

    std::string address = get_atyp_info(atyp, client_socket);
    unsigned short port = recv(client_socket, buffer, 2, 0);
    char response[] = {SOCKS5VER, 0x00, RESERVED, address[0], address[1], address[2], address[3], port};
    if (cmd == 0x01) {
        // set up TCP client and forward messages
        send(client_socket, response, sizeof(response), 0);
        tcp_client(client_socket, address, port);
        // send(client_socket, response, sizeof(response), 0);
    } else if (cmd == 0x02) {
        // BIND - CURRENTLY NOT SUPPORTED
        std::cerr << "Currently does not support BIND" << std::endl;
        close(client_socket);
        return;
    } else if (cmd == 0x03) {
        // UDP ASSOCIATE - WILL NOT IMPLEMENT
        std::cerr << "This Implemention skips UDP Associate" << std::endl;
        close(client_socket);
        return;
    } else {
        std::cerr << "Command does not exist" << std::endl;
        close(client_socket);
        return;
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
            close(server_fd);
            return -1;
        }

        // REQUESTS + REPLIES
        handle_socks_request(client_socket);

        std::cout << "Completed SOCKS 5" << std::endl;
    }

    close(server_fd);

    return 0;
}