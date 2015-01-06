//SSL-Server.c
#include <vector>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <iostream>
#include <exception>
#include <stdexcept>
#include <sstream>
#include <map>
#include <algorithm>

#include "message.hpp"

#define FAIL    -1

/* TODO:
    + wiecej niz 1 klient
    - rozglaszanie do wszystkich (na podstawie certyfikatow, tylko wybrani klienci)
    - w clientDesc informacja na podstawie certyfikatu (nie nickname'a) że klient może rozgłać wiadomości
    - komunikacja 1 do 1
*/

struct ClientDesc
{
    int descriptor;
    SSL* ssl;
    std::string name;

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
        SSL_library_init();
        serverContext_ = initServerContext();
        loadCertificates(serverContext_, certFile_, keyFile_);
        FD_ZERO(&clientsSet_);
        std::cout << "Server is ready for accepting connections." <<std::endl;
        listenForClients();
    }

private:
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

                clientDescriptors_[client] = desc;
                FD_SET(client, &clientsSet_);
                if(client > maximumClientDescriptor_) maximumClientDescriptor_ = client;
            }

            for (auto client : clientDescriptors_)
            {
                temporarySet_ = clientsSet_;
                select(maximumClientDescriptor_+1, &temporarySet_, NULL, NULL, NULL);
                //std::cout << "Checking client: " << client.descriptor << std::endl;
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

    void broadcastExcept(SSL* senderSsl, Message& msg)
    {
        for(auto& client: clientDescriptors_)
        {
            if(senderSsl != client.second.ssl)
            {
                SSL_write(client.second.ssl, msg.serialize(), msg.getMessageSize());
            }
        }     
    }

    void registerClient(Message& message, ClientDesc client)
    {
        std::cout << "New client register request received - " << message.getPayload() <<std::endl;
        clientNameToDescriptorBind_[std::string(message.getPayload())] = client.descriptor;
        std::cout << "Actual known clients = " << clientNameToDescriptorBind_.size() <<std::endl;
        Message clientInd(Message::CLIENT_CONN_IND, client.descriptor, 0, message.getPayload());
        broadcast(clientInd);
    }

    void serveClient(ClientDesc client)
    {   
        std::cout << "serveClient "<< client.descriptor << " method" << std::endl;
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

            default:
            {
                break;
            }
        }
  
        //socket = SSL_get_fd(ssl);     
        //SSL_free(ssl);   
        //close(socket); 
        //FD_CLR(client.descriptor, &clientsSet_);
        //clientDescriptors_.erase(std::remove(clientDescriptors_.begin(), clientDescriptors_.end(), client), clientDescriptors_.end());

    }

    void loadCertificates(SSL_CTX* ctx, std::string certFile, std::string keyFile)
    {
        
        if (SSL_CTX_load_verify_locations(ctx, certFile.c_str(), keyFile.c_str()) != 1)
            ERR_print_errors_fp(stderr);

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
            ERR_print_errors_fp(stderr);
        
        /* set the local certificate from CertFile */
        if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            abort();
        }
        /* set the private key from KeyFile (may be the same as CertFile) */
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            abort();
        }
        /* verify private key */
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
    std::map<std::string, int> clientNameToDescriptorBind_;
    std::string certFile_;
    std::string keyFile_;
    int port_;
};