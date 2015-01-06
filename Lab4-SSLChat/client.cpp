#include <csignal>
#include <string>

#include "client.hpp"

Client* clientPtr;

void INThandler(int signal);

int main(int argc, char** argv)
{
    signal(SIGINT, INThandler);
    Client client("127.0.0.1", atoi(argv[1]));
    clientPtr = &client;
    client.start();
}


void INThandler(int signal)
{
	clientPtr->INThandler();
}