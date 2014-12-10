#include <string>

#include "client.hpp"

int main(int argc, char** argv)
{
    Client client("127.0.0.1", atoi(argv[1]));
    client.start();
}