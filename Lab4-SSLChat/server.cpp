#include <csignal>
#include <iostream>
#include "server.hpp"

Server* servPtr;

void INThandler(int signal);

int main(int argc, char** argv)
{   
    signal(SIGINT, INThandler);
    std::string CertFile = "CA/certs/ca.crt";
    std::string KeyFile = "CA/private/ca.key";        
    Server server(atoi(argv[1]), CertFile, KeyFile);
    servPtr = &server;
    server.start();
}

void INThandler(int signal)
{
	servPtr->INThandler();
}