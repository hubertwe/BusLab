#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "message.hpp"

#define FAIL    -1

class Client
{
public:
	Client(std::string hostname, int port): hostname_(hostname), port_(port)
	{ }

	void start()
	{
		SSL_library_init();
		clientContext_ = initCTX();
		loadCertificates(clientContext_, certFile_, certFile_);
		serverDescriptor_ = openConnection(hostname_, port_);
		ssl_ = SSL_new(clientContext_);
		SSL_set_fd(ssl_, serverDescriptor_);
		if ( SSL_connect(ssl_) == FAIL )
        	ERR_print_errors_fp(stderr);
    	else
    	{  
    		handlerConnection();
		}

		SSL_free(ssl_);
		close(serverDescriptor_);
    	SSL_CTX_free(clientContext_);
	}

private:
	void loadCertificates(SSL_CTX* ctx, std::string certFile, std::string keyFile)
	{
	 /* set the local certificate from CertFile */
	    if ( SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
	    {
	        ERR_print_errors_fp(stderr);
	        abort();
	    }
	    /* set the private key from KeyFile (may be the same as CertFile) */
	    if ( SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
	    {
	        ERR_print_errors_fp(stderr);
	        abort();
	    }
	    /* verify private key */
	    if ( !SSL_CTX_check_private_key(ctx) )
	    {
	        fprintf(stderr, "Private key does not match the public certificate\n");
	        abort();
	    }
	}

	int openConnection(std::string hostname, int port)
	{   
	    int sd;
	    struct hostent *host;
	    struct sockaddr_in addr;

	    if ( (host = gethostbyname(hostname.c_str())) == NULL )
	    {
	        perror(hostname.c_str());
	        abort();
	    }
	    sd = socket(PF_INET, SOCK_STREAM, 0);
	    bzero(&addr, sizeof(addr));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(port);
	    addr.sin_addr.s_addr = *(long*)(host->h_addr);
	    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	    {
	        close(sd);
	        perror(hostname.c_str());
	        abort();
	    }
	    return sd;
	}

	SSL_CTX* initCTX(void)
	{   
	    SSL_METHOD *method;
	    SSL_CTX *ctx;

	    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	    SSL_load_error_strings();   /* Bring in and register error messages */
	    method = const_cast<SSL_METHOD*>(SSLv3_client_method());  /* Create new client-method instance */
	    ctx = SSL_CTX_new(method);   /* Create new context */
	    if ( ctx == NULL )
	    {
	        ERR_print_errors_fp(stderr);
	        abort();
	    }
	    return ctx;
	}

	void showCerts(SSL* ssl)
	{   
	    X509 *cert;
	    char *line;

	    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	    if ( cert != NULL )
	    {
	        printf("Server certificates:\n");
	        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	        printf("Subject: %s\n", line);
	        free(line);       /* free the malloc'ed string */
	        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	        printf("Issuer: %s\n", line);
	        free(line);       /* free the malloc'ed string */
	        X509_free(cert);     /* free the malloc'ed certificate copy */
	    }
	    else
	        printf("No certificates.\n");
	}

	void handlerConnection()
	{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl_));
        showCerts(ssl_);
        Message msgSend(Message::REGISTER_REQ, 1, "Hi Server!");  
        SSL_write(ssl_, msgSend.serialize(), msgSend.getMessageSize()); 
        Message serverResp; 
        bytes = SSL_read(ssl_, serverResp.getBuffer(), serverResp.getMessageSize());
		serverResp.deserialize();
		std::cout << "Server message:\t" << serverResp << std::endl;  
	}

	SSL_CTX *clientContext_;
	int serverDescriptor_;
	SSL *ssl_;
	char buf[1024];
    int bytes;
    std::string hostname_;
    int port_;
    std::string certFile_ = "CA/certs/hubert.pem";
};


