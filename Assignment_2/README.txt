gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0


Use 2048 bits for RSA, otherwise SSL_CTX_use_certificate_file() fails because
the key is very small.


Explaining the arguments of the following command briefly (source: the
corresponding manpages, i.e. man openssl, man req):

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem

req
	PKCS#10 X.509 Certificate Signing Request (CSR) Management.

-x509
	This option outputs a self signed certificate instead of a certificate
	request. 

-nodes
	If this option is specified then if a private key is created it will not be
	encrypted.

-days n
	When the -x509 option is being used this specifies the number of days to
	certify the certificate for. (In this case 365)

-newkey arg
	This option creates a new certificate request and a new private key. The
	argument takes one of several forms. rsa:nbits, where nbits is the number of
	bits, generates an RSA key nbits in size. (In this case 2048)

-keyout filename
	This gives the filename to write the newly created private key to. (In this
	case mycert.pem)

-out filename
	This specifies the output filename to write to or standard output by
	default. (In this case mycert.pem, same file as the keyout)



When we run
	sudo ./server 8082
8082 is the port number that the server listens. sudo is used because the server
program check inside it if root user is running the server.

When we run
	./client 127.0.0.1 8082
8082 is the server's port with which is going to communicate. 127.0.0.1 is the
IP of itself (localhost). This specific IP is the standard address for IPv4
loopback traffic.



The following site helped in server-client connection implementation:
https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/



For both server and client, the function ShowCerts has not been implemented due
to time restrictions.

