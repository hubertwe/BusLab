#include <csignal>
#include <iostream>

#include "server.hpp"

Server* servPtr;

void INThandler(int signal)
{
	servPtr->INThandler();
}

int main(int argc, char** argv)
{   
    if(argc < 2)
    {
    	std::cout << "Need more parameters!" <<std::endl;
    	std::cout << "Usage: " << argv[0] <<" port"<<std::endl;
    	std::cout << "       port     - server port"<<std::endl;
    	exit(1);
    }

    signal(SIGINT, INThandler);
    std::string CertFile = "CA/certs/server.crt";
    std::string KeyFile = "CA/private/server.key";        
    Server server(atoi(argv[1]), CertFile, KeyFile);
    servPtr = &server;
    server.start();
}

