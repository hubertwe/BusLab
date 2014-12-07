#include <string>

#include "client.hpp"

int main(int argv, char** argc)
{
    Client client("127.0.0.1", 56000);
    client.start();
}