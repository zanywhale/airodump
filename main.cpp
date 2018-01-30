#include <iostream>
#include <thread>
#include "packetHandler.h"
using namespace std;

int main(int argc, char *argv[])
{
    if(argc != 2){
        cout << "\033[1;32m Usage: airodump <Interface>\033[0m" << endl <<\
                "\033[1;31m Ex) airodump mon0\033[0m\n";
        exit(0);
    }
    else{
        // check interface is validation
        packetHandler *pktHandler = new packetHandler(argv[1]);
        std::thread t1 = pktHandler->hopping();
        std::thread t2 = pktHandler->dump();
    }

    return 0;
}
