#include <cstdint>
#include <string>
#include <bitset>


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

// Read RFC 1035 Section 4.1.1 for info on header
void deny_domain(uint8_t buf[]) {
	std::bitset<8> second_header_byte{buf[2]};
	std::bitset<8> third_header_byte{buf[3]};

	// Set QR bit to 1, change query to response
	second_header_byte.set(7);

	// Reset RCODE
	third_header_byte.reset(0);
	third_header_byte.reset(1);
	third_header_byte.reset(2);
	third_header_byte.reset(3);

	// Set RCODE value to 3 (Name Error)
	third_header_byte.flip(0);
	third_header_byte.flip(1);

	buf[2] = second_header_byte.to_ulong();
	buf[3] = third_header_byte.to_ulong();

	// Make ANCOUNT, NSCOUNT, and ARCOUNT bits all zero
	buf[6] = 0;
	buf[7] = 0;
	buf[8] = 0;
	buf[9] = 0;
	buf[10] = 0;
	buf[11] = 0;
}
