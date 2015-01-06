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
#include <exception>
#include <stdexcept>
#include <sstream>
#include <map>
#include "message.hpp"

#define FAIL    -1

class Client
{
public:
	Client(std::string hostname, int port): hostname_(hostname), port_(port), certFile_("CA/certs/hubert.pem")
	{
		actualUserDestination_ = 0;
	}

	void start()
	{
		try
		{
			
			SSL_library_init();
			clientContext_ = initCTX();
			loadCertificates(clientContext_, certFile_, certFile_);

			serverDescriptor_ = openConnection(hostname_, port_);
			ssl_ = SSL_new(clientContext_);

			startupScreen();
			
			SSL_set_fd(ssl_, serverDescriptor_);
			if ( SSL_connect(ssl_) == FAIL )
			{
	        	ERR_print_errors_fp(stderr);
	        	throw std::runtime_error("SSL error!");				
			}
 
	    	registerToServer();
	    	handleConnection();

			SSL_free(ssl_);
			close(serverDescriptor_);
	    	SSL_CTX_free(clientContext_);
	    }
		catch (std::exception& e)
		{
			std::cout << e.what() << std::endl;
			exit(1);
		}
	}

private:
	void send(Message& msg)
	{
		SSL_write(ssl_, msg.serialize(), msg.getMessageSize()); 	
	}

	Message receive()
	{
		Message serverResp;
		bytes = SSL_read(ssl_, serverResp.getBuffer(), serverResp.getMessageSize());
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


	void registerToServer()
	{       
        Message msgSend(Message::REGISTER_REQ, 0, 0, userName_.c_str());  
        send(msgSend);
	}

	void startupScreen()
	{
		std::cout << "         - Welcome in chat. -         " << std::endl;
		std::cout << " - Type !help for more instuctions. - " << std::endl;
		std::cout << "Please give your name [" << getCN() << "]: ";
		std::getline(std::cin, userName_);
		if(userName_.size() == 0)
		{
			userName_ = getCN();
		}

		if(userName_.size() <= 0)
		{
			throw std::runtime_error("User name was not correct");
		}

		std::cout << "Hi " << userName_ << ". You will be connected shortly." << std::endl;
	}

	std::string getCN()
	{
		X509 *crt = SSL_get_certificate(ssl_);

		std::string ownName (X509_NAME_oneline(X509_get_subject_name(crt), 0, 0));
		std::size_t startPos = ownName.find("/CN=");
		std::size_t endPos = ownName.find("/emailAddress=");

		const char CN_LEN = 4;
		ownName = ownName.substr(startPos+CN_LEN,endPos-(startPos+CN_LEN));  
		
		return ownName;
	}

	void loadCertificates(SSL_CTX* ctx, std::string certFile, std::string keyFile)
	{
	    if ( SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
	    {
	        ERR_print_errors_fp(stderr);
	        abort();
	    }
	    if ( SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0 )
	    {
	        ERR_print_errors_fp(stderr);
	        abort();
	    }
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

	void rememberNewClient(int clientId, std::string clientName)
	{
		std::cout << "New client indication received - " << clientName << std::endl;
		usersBindings_[clientId] = clientName;
	}

	void handleIncommingMessage(Message& msg)
	{
		switch (msg.getType())
		{
            case Message::CLIENT_CONN_IND:
            {
                rememberNewClient(msg.getClientSource(), std::string(msg.getPayload()));
                break;
            }

            default:
            {
            	std::cout << "Nothing to do\nServer message:\t" << msg << std::endl;
                break;
            }
		}
	}

	void handleConnection()
	{
		fd_set listenedDescriptors;
		FD_ZERO(&listenedDescriptors);
    	FD_SET(0, &listenedDescriptors);	//stdin
    	FD_SET(serverDescriptor_, &listenedDescriptors);

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl_));
		//showCerts(ssl_);
        while(true)
        {
        	fd_set temporaryDescriptors = listenedDescriptors;
        	select(serverDescriptor_+1, &temporaryDescriptors, NULL, NULL, NULL);
	        if(FD_ISSET(serverDescriptor_, &temporaryDescriptors))
	        {
	        	Message serverResp; 
	        	bytes = SSL_read(ssl_, serverResp.getBuffer(), serverResp.getMessageSize());
				serverResp.deserialize();
				handleIncommingMessage(serverResp);
	        }
	        else if (FD_ISSET(0, &temporaryDescriptors))
	        {
	        	std::string msgText;
	        	std::getline(std::cin, msgText);
	        	if(isCommand(msgText))
	        	{
	        		processCommand(msgText);
	        	}
	        	else
	        	{
	        		if(actualUserDestination_ == 0)
	        		{
	        			std::cout << "No user selected. Can't send message" << std::endl;
	        		}
	        		else
	        		{
	        			Message msgSend(Message::TEXT_MSG, 0, actualUserDestination_, msgText.c_str());  
	        			send(msgSend);
	        		}
	        	}
	        }
	    }
	}

	void sendBroadcastMessage()
	{
		std::cout << "Not implemented yet!" <<std::endl;
	}

	void selectUser()
	{
		printKnownUsers();
		std::cout << "Give one of above id's: ";
		std::string selectedIdStr;
		std::getline(std::cin, selectedIdStr);
		int selectedId = atoi(selectedIdStr.c_str());

		if(usersBindings_.find(selectedId) != usersBindings_.end())
		{
			actualUserDestination_ = selectedId;
			std::cout << "Actual selected userId: "<< actualUserDestination_  << " - Name: " << usersBindings_[actualUserDestination_]<<std::endl;

		}
		else
		{
			std::cout << "Selected userId: "<< selectedId << " doesn't exists" <<std::endl;
		}

	}

	void printKnownUsers()
	{
		std::cout << "Actual users:" <<std::endl;
		std::cout << "id - name" <<std::endl;
		for(auto& user : usersBindings_)
		{
			std::cout << user.first << " - " << user.second <<std::endl;
		}

	}

	void printHelp()
	{
		std::cout << 	"Client help:" << std::endl <<
						"------------" << std::endl <<
						"Avaliable commands:" << std::endl <<
						"!broadcast - broadcast message to all users" << std::endl <<
						"!help - print this help" << std::endl <<
						"!users - print users connected to server" << std::endl <<
						"!selectuser - select user to talk with" << std::endl <<
						"!quit - exits client application" << std::endl;
	}
	bool isCommand(std::string& line)
	{
		if(line.size()>0)
		{
			if(line.at(0) == '!') 
			{
				return true;
			}
			else return false;
		}
		else return false;
	}

	void processCommand(std::string& line)
	{
		if(line  == "!help")
		{
			printHelp();
		}
		else if (line == "!broadcast")
		{
			sendBroadcastMessage();
		}
		else if (line == "!users")
		{
			printKnownUsers();
		}
		else if (line == "!selectuser")
		{
			selectUser();
		}		
		else if (line == "!quit")
		{
			exit(0);
		}
		else
		{
			std::cout << "Unrecognized command: " << line <<std::endl;
		}
	}

	SSL_CTX *clientContext_;
	int serverDescriptor_;
	SSL *ssl_;
	char buf[1024];
    int bytes;
    std::string hostname_;
    int port_;
    std::string certFile_;
    std::string userName_;
    int actualUserDestination_;
    std::map<int,std::string> usersBindings_;
};


