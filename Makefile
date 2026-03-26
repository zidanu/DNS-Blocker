CXX = g++
CXXFLAGS = -Wall -Wextra -g

build:
	$(CXX) main.cpp -o dns_blocker $(CXXFLAGS)

clean:
	rm -f dns_blocker
