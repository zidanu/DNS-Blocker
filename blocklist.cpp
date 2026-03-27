#include <iostream>
#include <unordered_set>
#include <fstream>

void load_blocklist(std::unordered_set<std::string> &block_list, std::ifstream &file) {
	std::string line;
	// Reads each line of file
	while (std::getline(file, line)) {
		if (line[0] >= 48 && line[0] <= 57) {
			std::string domain;

			bool passed_ip_addr = false;
			bool reached_domain_name = false;

			int i = 0;
			// Skipping through the ip address part of the line (Ex: 127.0.0.1  google.com)
			while (!passed_ip_addr) {
				i++;
				if (line[i] == ' ' || line[i] == '\t') {
					passed_ip_addr = true;
				}
			}

			// Skipping through the white space in between the ip and domain (Ex: 127.0.0.1  google.com)
			while (!reached_domain_name && passed_ip_addr) {
				i++;
				if (line[i] != ' ' && line[i] != '\t') {
					reached_domain_name = true;
				}
			}

			// Parsing the domain and inserting the domain string to the block_list set
			while (reached_domain_name && i != line.length()) {
				if (line[i] != ' ' && line[i] != '\t') {
					domain.push_back(line[i]);
				}
				if (i == (line.length()-1) || line[i] == ' ' || line[i] == '\t') {
					if (domain != "") {
						block_list.insert(domain);
						domain = "";
					}
				}
				i++;
			}
		} else {
			continue;
		}
	}
	file.close();
}

void update_blocklist(std::unordered_set<std::string> &block_list, char* &blockfile_path) {
	std::ifstream file(blockfile_path);
	if (!file.is_open()) {
		std::cerr << "Error occurred with std::ifstream object initialization\n";
		return;
	}

	std::string line;
	// Reads each line of file
	while (std::getline(file, line)) {
		if (line[0] >= 48 && line[0] <= 57) {
			std::string domain;

			bool passed_ip_addr = false;
			bool reached_domain_name = false;

			int i = 0;
			// Skipping through the ip address part of the line (Ex: 127.0.0.1  google.com)
			while (!passed_ip_addr) {
				i++;
				if (line[i] == ' ' || line[i] == '\t') {
					passed_ip_addr = true;
				}
			}

			// Skipping through the white space in between the ip and domain (Ex: 127.0.0.1  google.com)
			while (!reached_domain_name && passed_ip_addr) {
				i++;
				if (line[i] != ' ' && line[i] != '\t') {
					reached_domain_name = true;
				}
			}

			// Parsing the domain and inserting the domain string to the block_list set
			while (reached_domain_name && i != line.length()) {
				if (line[i] != ' ' && line[i] != '\t') {
					domain.push_back(line[i]);
				}
				if (i == (line.length()-1) || line[i] == ' ' || line[i] == '\t') {
					if (domain != "") {
						block_list.insert(domain);
						domain = "";
					}
				}
				i++;
			}
		} else {
			continue;
		}
	}
	file.close();
}
