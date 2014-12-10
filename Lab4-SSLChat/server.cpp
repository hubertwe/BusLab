#include <csignal>
#include <iostream>

#include "server.hpp"

Server* servPtr;

int main(int argc, char** argv)
{   
    std::string CertFile = "CA/certs/ca.crt";
    std::string KeyFile = "CA/private/ca.key";        
    Server server(atoi(argv[1]), CertFile, KeyFile);
    servPtr = &server;
    server.start();
}