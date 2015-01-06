#include <csignal>
#include <iostream>
#include "server.hpp"

Server* servPtr;

void INThandler(int signal);

int main(int argc, char** argv)
{   
    signal(SIGINT, INThandler);
    std::string CertFile = "CA/certs/server.crt";
    std::string KeyFile = "CA/private/server.key";        
    Server server(atoi(argv[1]), CertFile, KeyFile);
    servPtr = &server;
    server.start();
}

void INThandler(int signal)
{
	servPtr->INThandler();
}