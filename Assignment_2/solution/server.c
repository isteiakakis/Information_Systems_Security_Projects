#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

SSL_CTX* InitServerCTX(void)
{
	/* load & register all cryptos, etc. */
	OpenSSL_add_all_algorithms();

	/* load all error messages */
	SSL_load_error_strings();

	/* create new server-method instance */
	const SSL_METHOD *server_method = TLSv1_2_server_method(); // Use TLS1.2 protocol as the instructions specify

	/* create new context from method */
	SSL_CTX *ctx = SSL_CTX_new(server_method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) != 1){
		fprintf(stderr, "Certificate file loading error.\n");
		exit(1);
	}

    /* set the private key from KeyFile (may be the same as CertFile) */
    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) != 1){
		fprintf(stderr, "Private key file loading error.\n");
		exit(1);
	}

    /* verify private key */
    if(SSL_CTX_check_private_key(ctx) != 1){
		fprintf(stderr, "Private key check failed.\n");
		exit(1);
	}
}
//void ShowCerts(SSL* ssl)
//{
//	/* Get certificates (if available) */
//    if ( cert != NULL )
//    {
//        printf("Server certificates:\n");
//        /* */
//        printf("Subject: %s\n", line);
//        free(line);
//        /* */
//        printf("Issuer: %s\n", line);
//        free(line);
//    }
//    else
//        printf("No certificates.\n");
//}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    const char* ServerResponse = 
		"<Body>\n"
        "\t<Name>sousi.com</Name>\n"
        "\t<year>1.5</year>\n"
        "\t<BlogType>Embedede and c c++</BlogType>\n"
        "\t<Author>John Johny</Author>\n"
        "</Body>\n";

    const char *cpValidMessage = "<Body>\n\t<UserName>sousi</UserName>\n\t<Password>123</Password>\n</Body>";
	/* do SSL-protocol accept */
	if(SSL_accept(ssl) != 1){
		fprintf(stderr, "SSL accept failed.\n");
		exit(1);
	}else{
		char client_reply[16000] = {0};
		if(SSL_read(ssl, client_reply, 16000) <= 0){
			fprintf(stderr, "SSL read error.\n");
			exit(1);
		}

		printf("Client reply:\n%s\n", client_reply);

		if(strcmp(client_reply, cpValidMessage) == 0){
			SSL_write(ssl, ServerResponse, strlen(ServerResponse));
		}else{
    		/*else print "Invalid Message" */
			char *invalid_msg = "Invalid Message";
			SSL_write(ssl, invalid_msg, strlen(invalid_msg));
		}
	}
  
	/* get socket connection */
	int client_fd = SSL_get_fd(ssl);

	/* release SSL state */
	SSL_free(ssl);

    /* close connection */
	close(client_fd);
}

int main(int count, char *Argc[])
{

	//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }

	// Get port
	int port = atoi(Argc[1]);

    // Initialize the SSL library
	SSL_library_init();

    /* initialize SSL */
	SSL_CTX *ssl_ctx = InitServerCTX();

    /* load certs */
	LoadCertificates(ssl_ctx, "mycert.pem", "mycert.pem");

    /* create server socket */
	int server_fd = OpenListener(port);

	// Begin the connection process
	struct sockaddr_in addr;
	socklen_t addr_len;
	int client_fd;
	SSL *ssl;

    while (1)
    {
		/* accept connection as usual */
		addr_len = sizeof addr;
		bzero(&addr, addr_len);
		client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len); // server is listening from client now
		
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		/* get new SSL state with context */
		ssl = SSL_new(ssl_ctx);

		/* set connection socket to SSL state */
		SSL_set_fd(ssl, client_fd);

		/* service connection */
		Servlet(ssl);
    }

	/* close server socket */
	close(server_fd);

	close(client_fd); // also close client file descriptor

	/* release context */
	SSL_CTX_free(ssl_ctx);
}
