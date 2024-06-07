all:
	g++ -Wall src/main.cpp -lpcap -o bin/nflog2eth
clean: 
	rm -f bin/nflog2eth