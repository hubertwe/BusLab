#!/bin/bash
clear
g++ -std=c++0x -Wall -o server server.cpp -lssl -lcrypto -lpthread
g++ -std=c++0x -Wall -o client client.cpp -lssl -lcrypto