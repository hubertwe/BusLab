#include <algorithm>
#include <arpa/inet.h>
#include <errno.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <malloc.h>
#include <map>
#include <netinet/in.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <resolv.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdexcept>
#include <sstream>
#include <set>
#include <unistd.h>
#include <vector>

#include "message.hpp"

#define FAIL    -1

struct ClientDesc
{
    int descriptor;
    SSL* ssl;
    bool canBroadcast;

    bool operator==(const ClientDesc& cli)
    {
        return ((descriptor == cli.descriptor) && (ssl = cli.ssl));
    }
};

class Server
{
public:
    Server(int port, std::string certFile, std::string keyFile) 
    : certFile_(certFile), keyFile_(keyFile), port_(port) {}
    
    void start() 
    {
        try
        {
            readClientsThatCanBroadcastFromFile();
            SSL_library_init();
            serverContext_ = initServerContext();
            loadCertificates(serverContext_, certFile_, keyFile_);
            FD_ZERO(&clientsSet_);
            std::cout << "Server is ready for accepting connections." <<std::endl;
            listenForClients();
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
            exit(1);
        }
    }

    void INThandler()
    {
        std::cout << std::endl << "Killing server by INT signal... Need to tell all clients about it." << std::endl;
        Message msg(Message::SERVER_DIED, 0, 0, "");
        broadcast(msg);
        exit(0);
    }

private:
    void readClientsThatCanBroadcastFromFile()
    {
        std::cout << "Reading broadcast users from file..." << std::endl;
        std::ifstream file ("clientBroadcast.cfg");
        if(file.is_open())
        {
            std::string username;
            while( std::getline (file, username) )
            {
                usersThatCanBroadcast_.insert(username);
            }
            file.close();
          }
    }

    bool isNameOnBroadcastList(std::string name)
    {
        if(usersThatCanBroadcast_.find(name) != usersThatCanBroadcast_.end())
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    void listenForClients()
    {
        listener_ = openListener(port_);
        maximumClientDescriptor_ = listener_;
        FD_SET(listener_, &clientsSet_);

        while(true)
        {
            temporarySet_ = clientsSet_;
            select(maximumClientDescriptor_+1, &temporarySet_, NULL, NULL, NULL);

            if(FD_ISSET(listener_, &temporarySet_))
            {
                std::cout << "New client connection..." << std::endl;
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);
                SSL *ssl;

                int client = accept(listener_, (struct sockaddr*)&addr, &len);  
                ssl = SSL_new(serverContext_);  

                SSL_set_fd(ssl, client);

                if ( SSL_accept(ssl) == FAIL )
                {
                    ERR_print_errors_fp(stderr);
                }

                ClientDesc desc;
                desc.descriptor = client;
                desc.ssl = ssl;

                std::cout << "Connected client real name: " << getClientCN(ssl) << std::endl;
                desc.canBroadcast = isNameOnBroadcastList(getClientCN(ssl));

                clientDescriptors_[client] = desc;
                FD_SET(client, &clientsSet_);
                if(client > maximumClientDescriptor_) maximumClientDescriptor_ = client;
            }

            for (auto client : clientDescriptors_)
            {
                temporarySet_ = clientsSet_;
                select(maximumClientDescriptor_+1, &temporarySet_, NULL, NULL, NULL);
                if(FD_ISSET(client.second.descriptor, &temporarySet_))
                {
                    serveClient(client.second);
                }
            }
        }
    }

    void send(SSL* ssl, Message& msg)
    {
        SSL_write(ssl, msg.serialize(), msg.getMessageSize());     
    }

    Message receive(SSL* ssl)
    {
        Message serverResp;
        int bytes = SSL_read(ssl, serverResp.getBuffer(), serverResp.getMessageSize());
        serverResp.deserialize();
        std::stringstream ss;
        ss << serverResp;

        if ((bytes < 0) || (!serverResp.isStatusValid()))
        {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Receive error!" + ss.str());
        }
        return serverResp;
    }

    void broadcast(Message& msg)
    {
        for(auto& client: clientDescriptors_)
        {
            SSL_write(client.second.ssl, msg.serialize(), msg.getMessageSize());
        }     
    }

    void broadcastInfoAboutAllConnectedClients()
    {
        for(auto& known: clientNameToDescriptorBind_)
        {
            Message clientInd(Message::CLIENT_CONN_IND, known.first, 0, known.second);
            broadcast(clientInd);  
        }
    }

    void broadcastInfoAboutQuitClient(ClientDesc client)
    {
        Message clientInd(Message::CLIENT_QUIT_IND, client.descriptor, 0, "");
        broadcast(clientInd);
    }

    bool isClientAbleToBroadcastMessage(int clientId)
    {
        return clientDescriptors_[clientId].canBroadcast; // for now everyone can broadcast
    }

    void broadcastTextMessageToAll(Message& message, ClientDesc client)
    {
        message.setClientSource(client.descriptor);
        if(isClientAbleToBroadcastMessage(client.descriptor))
        {
            broadcast(message); 
        }
        else
        {
            std::cout << "Client: " << client.descriptor << " can't broadcast messages due to certificate name restrictions." << std::endl;
        }

    }

    void registerClient(Message& message, ClientDesc client)
    {
        std::cout << "New client register request received - " << message.getPayload() <<std::endl;
        clientNameToDescriptorBind_[client.descriptor] = std::string(message.getPayload());
        broadcastInfoAboutAllConnectedClients();
    }

    void forwardMessage(Message& message, ClientDesc client)
    {
        message.setClientSource(client.descriptor);
        int clientDest = message.getClientDestination();
        std::cout << "Forwarding message from " << 
        clientNameToDescriptorBind_[client.descriptor] << " to "  <<
        clientNameToDescriptorBind_[clientDest] << std::endl;
        send(clientDescriptors_[clientDest].ssl ,message);
    }

    void forgetAboutClient(ClientDesc client)
    {
        clientDescriptors_.erase(client.descriptor);
        clientNameToDescriptorBind_.erase(client.descriptor);
        FD_CLR(client.descriptor, &clientsSet_);
    }

    void serveClient(ClientDesc client)
    {   
        SSL* ssl;
        ssl = client.ssl;

        Message req;
        req = receive(ssl);

        switch (req.getType())
        {
            case Message::REGISTER_REQ :
            {
                registerClient(req, client);
                break;
            }

            case Message::TEXT_MSG : 
            {
                forwardMessage(req, client);
                break;
            }

            case Message::BROADCAST_MSG : 
            {
                broadcastTextMessageToAll(req, client);
                break;
            }

            case Message::CLIENT_QUIT_IND : 
            {
                forgetAboutClient(client);
                broadcastInfoAboutQuitClient(client);
                break;
            }

            default:
            {
                break;
            }
        }
    }

    std::string getClientCN(SSL *ssl)
    {
        X509 *crt = SSL_get_peer_certificate(ssl);

        std::string ownName (X509_NAME_oneline(X509_get_subject_name(crt), 0, 0));

        std::size_t startPos = ownName.find("/CN=");
        std::size_t endPos = ownName.find("/emailAddress=");

        const char CN_LEN = 4;
        ownName = ownName.substr(startPos+CN_LEN,endPos-(startPos+CN_LEN));  
        
        return ownName;
    }

    void loadCertificates(SSL_CTX* ctx, std::string certFile, std::string keyFile)
    {
        
        if (SSL_CTX_load_verify_locations(ctx, certFile.c_str(), keyFile.c_str()) != 1)
            ERR_print_errors_fp(stderr);

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
            ERR_print_errors_fp(stderr);
        
        if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            abort();
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            abort();
        }

        if (!SSL_CTX_check_private_key(ctx))
        {
            fprintf(stderr, "Private key does not match the public certificate\n");
            abort();
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    SSL_CTX* initServerContext()
    {   
        SSL_METHOD *method;
        SSL_CTX *ctx;

        OpenSSL_add_all_algorithms(); 
        SSL_load_error_strings();   
        method = const_cast<SSL_METHOD*>(SSLv3_server_method());  
        ctx = SSL_CTX_new(method); 
        if ( ctx == NULL )
        {
            ERR_print_errors_fp(stderr);
            abort();
        }
        return ctx;
    }

    int openListener(int port)
    {   
        int socketDescriptor;
        struct sockaddr_in addr;

        socketDescriptor = socket(PF_INET, SOCK_STREAM, 0);
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if ( bind(socketDescriptor, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
        {
            perror("Can't bind port");
            abort();
        }
        if ( listen(socketDescriptor, 10) != 0 )
        {
            perror("Can't configure listening port");
            abort();
        }
        return socketDescriptor;
    }

    SSL_CTX *serverContext_;
    int listener_;
    int maximumClientDescriptor_;
    fd_set temporarySet_;
    fd_set clientsSet_;
    std::map<int, ClientDesc> clientDescriptors_;
    std::map<int, std::string> clientNameToDescriptorBind_;
    std::set<std::string> usersThatCanBroadcast_;
    std::string certFile_;
    std::string keyFile_;
    int port_;
};