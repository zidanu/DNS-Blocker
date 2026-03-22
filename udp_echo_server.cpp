#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 6464

int main() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror("Error occurred with socket()");
		return 1;
	}

	struct sockaddr_in server_addr;
	socklen_t server_len = sizeof(server_addr);
	memset(&server_addr, 0, server_len);
	server_addr.sin_port = htons(PORT);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr*)&server_addr, server_len) == -1) {
		perror("Error occurred with bind()");
		return 1;
	}

	std::cout << "Listening on port " << PORT << "...\n";

	uint8_t buf[512];

	while (true) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);

		ssize_t n = recvfrom(fd, buf, 512, 0, (struct sockaddr*) &client_addr, (socklen_t*) &client_len);
		if (n == -1) {
			perror("Error occurred with recvfrom()");
			break;
		}

		std::cout << "Received " << n << " bytes\n";

		if (sendto(fd, buf, n, 0, (struct sockaddr*) &client_addr, client_len) == -1) {
			perror("Error occurred with sendto()");
			break;
		}
	}
	if (close(fd) == -1) {
		perror("Error occurred with close()");
		return 1;
	}

	return 0;
}
