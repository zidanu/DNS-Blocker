#include <cstdint>
#include <string>


std::string parse_domain_from_query(const uint8_t buf[], int offset) {
	std::string domain;
	int i = offset;
	while (buf[i] != '\0') {
		// <= 63 because max length of top-level domains is 63
		if (i > offset && buf[i] <= 63) {
			domain.push_back('.');
		} else if (i > offset) {
			domain.push_back(buf[i]);
		}
		i++;
	}
	return domain;
}
