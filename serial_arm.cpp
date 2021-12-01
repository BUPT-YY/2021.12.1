#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
using namespace std;

ofstream ofs;



int main() {
	ofs.open("/dev/ttyS0", ios::out | ios::app);
	int user = 3;

	char write;
for(;;)	 {
	if(user == 1)
		user = 3;
	else 
		user = 1;


	ofs.put('E').put('B').put('9').put('1').put('E').put('B').put('9').put('1');


	write = (char)(user + 'a');
	ofs.put(write);
	
	double valDouble = 0;
	for(int i = 0; i < 27; ++i) {
		valDouble = i/2.0;
		uint64_t bitsDoubleValue = *(reinterpret_cast<uint64_t*>(&valDouble));
		for(int j = 0; j < 16; ++j) {			
			write = (char)(((bitsDoubleValue >> (60-j*4)) & 0xF) +'a');
			ofs.put(write);
		}
	}

	int valint = 0;	
	for(int i = 0; i < 3; ++i) {
		valint = 3*i + 25;

		uint32_t bitsIntValue = *(reinterpret_cast<uint32_t*>(&valint));
		for(int j = 0; j < 8; ++j) {			
			write = (char)(((bitsIntValue >> (28-j*4)) & 0xF)+'a');
			ofs.put(write);
		}
	}
	ofs.put('\n');
}

	return 0;
}
