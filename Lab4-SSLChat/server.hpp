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
#include <algorithm>

#include "message.hpp"

#define FAIL    -1

/* TODO:
    - wiecej niz 1 klient
    - rozglaszanie do wszystkich (na podstawie certyfikatow, tylko wybrani klienci)
    - komunikacja 1 do 1
*/

struct ClientDesc
{
    int descriptor;
    SSL* ssl;

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
            temporartSet_ = clientsSet_;
            select(maximumClientDescriptor_+1, &temporartSet_, NULL, NULL, NULL);

            if(FD_ISSET(listener_, &temporartSet_))
            {
                std::cout << "New client connection..." << std::endl;
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);
                SSL *ssl;

                int client = accept(listener_, (struct sockaddr*)&addr, &len);  
                ssl = SSL_new(serverContext_);           
                SSL_set_fd(ssl, client);

                ClientDesc desc;
                desc.descriptor = client;
                desc.ssl = ssl;

                clientDescriptors_.push_back(desc);
                FD_SET(client, &clientsSet_);
                if(client > maximumClientDescriptor_) maximumClientDescriptor_ = client;
            }

            for (auto client : clientDescriptors_)
            {
                if(FD_ISSET(client.descriptor, &clientsSet_))
                {
                    serveClient(client);
                }
            }
        }
    }

    void serveClient(ClientDesc client)
    {   
        SSL* ssl;
        ssl = client.ssl;
        int socket, bytes;

        if ( SSL_accept(ssl) == FAIL )
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            Message req;
            bytes = SSL_read(ssl, req.getBuffer(), req.getMessageSize());
            req.deserialize();
            if ( bytes > 0 )
            {
                std::cout << bytes << "bytes received" << std::endl;
                std::cout << "Message size bytes " << req.getMessageSize() << std::endl;
                std::cout << "Client message:\t" << req << std::endl;

                Message resp(Message::REGISTER_RESP, 0, "Hello Client!"); 
                SSL_write(ssl, resp.serialize(), resp.getMessageSize());
            }
            else
            {
                ERR_print_errors_fp(stderr);
            }
        }

        socket = SSL_get_fd(ssl);     
        SSL_free(ssl);   
        close(socket); 
        FD_CLR(client.descriptor, &clientsSet_);
        clientDescriptors_.erase(std::remove(clientDescriptors_.begin(), clientDescriptors_.end(), client), clientDescriptors_.end());

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
    fd_set temporartSet_;
    fd_set clientsSet_;
    std::vector<ClientDesc> clientDescriptors_;
    std::string certFile_;
    std::string keyFile_;
    int port_;
    std::vector<pthread_t> threads_;
};