all:
	g++ -std=c++17 -O2 -o 1m-block 1m-block.cpp -lnetfilter_queue

clean:
	rm -f 1m-block
