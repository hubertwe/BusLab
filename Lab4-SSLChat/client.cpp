#include <csignal>
#include <iostream>

#include "client.hpp"

Client* clientPtr;

void INThandler(int signal)
{
	clientPtr->INThandler();
}

int main(int argc, char** argv)
{
    if(argc < 4)
    {
    	std::cout << "Need more parameters!" <<std::endl;
    	std::cout << "Usage: " << argv[0] <<" ip_addr port certFile"<<std::endl;
    	std::cout << "       ip_addr  - server ip address"<<std::endl;
    	std::cout << "       port     - server port"<<std::endl;
    	std::cout << "       certFile - *.pem file used for authenticaton"<<std::endl;
    	exit(1);
    }

    signal(SIGINT, INThandler);
    Client client(argv[1], atoi(argv[2]), argv[3]);
    clientPtr = &client;
    client.start();
}


