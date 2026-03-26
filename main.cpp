#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unordered_set>
#include<fstream>

#include "packet_parser.cpp"
#include "blocklist.cpp"

#define PORT 6464
#define DNS_RESOLVER_PORT 53
#define DNS_RES_IP "8.8.8.8"

std::unordered_set<std::string> blocklist = {};

int main(int argc, char* argv[]) {
	if (argc != 2) {
		std::cerr << "Proper usage: ./dns_blocker blocklist\n";
		return 1;
	}

	std::ifstream block_file(argv[1]);
	if (!block_file.is_open()) {
		std::cerr << "Error occurred with std::ifstream object initialization\n";
		return 1;
	}

	load_blocklist(blocklist, block_file);

	// std::cout << "Block list:" << '\n';
	//
	// for (const auto& elem : block_list) {
	// 	std::cout << elem << elem.length() << '\n';
	// }
	//
	int fd_client_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd_client_socket == -1) {
		perror("Error occurred with socket()");
		return 1;
	}

	int fd_rsolvr_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd_rsolvr_socket == -1) {
		perror("Error occurred with socket()");
		return 1;
	}

	struct sockaddr_in server_addr;
	socklen_t server_len = sizeof(server_addr);
	memset(&server_addr, 0, server_len);
	server_addr.sin_port = htons(PORT);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd_client_socket, (struct sockaddr*)&server_addr, server_len) == -1) {
		perror("Error occurred with bind()");
		return 1;
	}

	std::cout << "Listening on port " << PORT << "...\n";


	uint8_t buf[512];

	const char* dns_resolver_ip = DNS_RES_IP;
	struct in_addr ipv4_binary;

	if (inet_pton(AF_INET, dns_resolver_ip, &ipv4_binary) != 1) {
		std::cerr << "Error occurred with inet_pton()\n";
		return 1;
	}

	struct sockaddr_in rsolvr_addr;
	socklen_t rsolvr_len = sizeof(rsolvr_addr);
	memset(&rsolvr_addr, 0, rsolvr_len);
	rsolvr_addr.sin_port = htons(DNS_RESOLVER_PORT);
	rsolvr_addr.sin_family = AF_INET;
	rsolvr_addr.sin_addr.s_addr = ipv4_binary.s_addr;

	while (true) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);

		struct sockaddr_in client2_addr;;
		socklen_t client2_len = sizeof(client2_addr);

		ssize_t n = recvfrom(fd_client_socket, buf, 512, 0, (struct sockaddr*) &client_addr, (socklen_t*) &client_len);
		if (n == -1) {
			perror("Error occurred with recvfrom()");
			break;
		}

		std::cout << "Received " << n << " bytes\n";

		std::string domain = parse_domain_from_query(buf, 12);
		if (blocklist.find(domain) != blocklist.end()) {
			int cutoff = deny_domain(buf);
			if (sendto(fd_client_socket, buf, cutoff, 0, (struct sockaddr*) &client_addr, client_len) == -1) {
				perror("Error occurred with sendto()");
				break;
			}
			continue;
		}

		if (sendto(fd_rsolvr_socket, buf, n, 0, (struct sockaddr*) &rsolvr_addr, rsolvr_len) == -1) {
			perror("Error occurred with sendto()");
			break;
		}

		ssize_t dns_resolver_response = recvfrom(fd_rsolvr_socket, buf, 512, 0, (struct sockaddr*) &client2_addr, (socklen_t*) &client2_len);
		if (dns_resolver_response == -1) {
			perror("Error occurred with recvfrom()");
			break;
		}

		if (sendto(fd_client_socket, buf, dns_resolver_response, 0, (struct sockaddr*) &client_addr, client_len) == -1) {
			perror("Error occurred with sendto()");
			break;
		}
	}
	if (close(fd_client_socket) == -1) {
		perror("Error occurred with close()");
		return 1;
	}

	return 0;
}
