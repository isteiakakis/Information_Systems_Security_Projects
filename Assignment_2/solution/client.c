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
#include <netinet/in.h>
#include <arpa/inet.h>


#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{
	// Create socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(socket_fd == -1){
		fprintf(stderr, "Socket creation error.\n");
		exit(1);
	}
	
	// Build sockaddr_in for server
	struct sockaddr_in client_addr;
	bzero(&client_addr, sizeof client_addr);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);
    client_addr.sin_addr.s_addr = inet_addr(hostname);
	
	// Perform connection
    if (connect(socket_fd, (struct sockaddr *)&client_addr, sizeof client_addr) != 0){
		fprintf(stderr, "Socket connection error.\n");
		exit(1);
    }

    return socket_fd;
}

SSL_CTX* InitCTX(void)
{
	/* Load cryptos, et.al. */
	OpenSSL_add_all_algorithms();

	/* Bring in and register error messages */
	SSL_load_error_strings();

	/* Create new client-method instance */
	const SSL_METHOD *client_method = TLSv1_2_client_method(); // Use TLS1.2 protocol as the instructions specify

	/* Create new context */
	SSL_CTX *ctx = SSL_CTX_new(client_method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

//void ShowCerts(SSL* ssl)
//{
//	/* get the server's certificate */
//    if ( cert != NULL )
//    {
//        printf("Server certificates:\n");
//        /* */
//        printf("Subject: %s\n", line);
//       	/* */
//        printf("Issuer: %s\n", line);
//        free(line);
//    }
//    else
//        printf("Info: No client certificates configured.\n");
//}

void *xmalloc(size_t size){
	void *retval = malloc(size);
	if(retval==NULL){
		fprintf(stderr, "malloc error.\n");
		exit(1);
	}
	return retval;
}

int main(int count, char *strings[])
{
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

	// Get the hostname and the port
	char *hostname = strings[1];
	int port = atoi(strings[2]);

	// Open connection to server
	int server_fd = OpenConnection(hostname, port);

	// Initialize SSL library and attach the connection to SSL
	SSL_library_init();
	SSL_CTX *ssl_ctx = InitCTX(); // Initialize ssl context

    /* create new SSL connection state */
	SSL *ssl = SSL_new(ssl_ctx);
	if(ssl == NULL){
		fprintf(stderr, "SSL object creation error.\n");
		exit(1);
	}

	/* attach the socket descriptor */
	if(SSL_set_fd(ssl, server_fd) == 0){
		fprintf(stderr, "Attaching the socket descriptor error.\n");
		exit(1);
	}

	/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    { // Successful connection to server
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        printf("Enter the User Name : ");
        scanf("%s", acUsername);
        printf("Enter the Password : ");
        scanf("%s", acPassword);

		/* construct reply */
        const char *cpRequestMessage_format = "<Body>\n\t<UserName>%s</UserName>\n\t<Password>%s</Password>\n</Body>";
		char *cpRequestMessage = xmalloc(sizeof(char) * (strlen(cpRequestMessage_format)+strlen(acUsername)+strlen(acPassword)+1)); // allocate the appropriate memory for the request message
		sprintf(cpRequestMessage, cpRequestMessage_format, acUsername, acPassword);

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

   		/* get any certs */
		//ShowCerts(ssl);

        /* encrypt & send message */
		SSL_write(ssl, cpRequestMessage, sizeof(char)*(strlen(cpRequestMessage)+1)); // write bytes to the TLS connection (don't forget '\0')

        /* get reply & decrypt */
		char server_reply[16000] = {0};
		if(SSL_read(ssl, server_reply, 16000) <= 0){
			fprintf(stderr, "SSL read error.\n");
			exit(1);
		}

		printf("Server reply:\n%s\n", server_reply);

	    /* release connection state */
		SSL_free(ssl);
    }

	/* close socket */
	close(server_fd);
	
	/* release context */
	SSL_CTX_free(ssl_ctx);

    return 0;
}
