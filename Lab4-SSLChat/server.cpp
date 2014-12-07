#include <csignal>
#include <iostream>

#include "server.hpp"

Server* servPtr;

int main()
{   
    std::string CertFile = "CA/certs/ca.crt";
    std::string KeyFile = "CA/private/ca.key";        
    Server server(56005, CertFile, KeyFile);
    servPtr = &server;
    server.start();
}