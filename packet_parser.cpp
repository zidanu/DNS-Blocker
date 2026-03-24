#include <cstdint>
#include <string>
#include <unistd.h>


std::string parse_domain(const uint8_t buf[], int offset) {
	std::string domain;
	int i = offset;
	while (buf[i] != '\0') {
		// <= 63 because max length of top-level domains is 63
		if (i > offset && buf[i] <= 63) {
			domain.push_back('.');
		} else {
			domain.push_back(buf[i]);
		}
		i++;
	}
	return domain;
}
