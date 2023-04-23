#include <curses.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bio.h> // encode to base64
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <getopt.h>
#include <string>
using std::string;
#include <deque>
using std::deque;
#include <pthread.h>
#include <utility>
using std::pair;
#include "dh.h"
#include <cstring>

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */
static pthread_t tcurses;   /* setup curses and draw messages from queue */
void* cursesthread(void*);  /* for tcurses */
/* tcurses will get a queue full of these and redraw the appropriate windows */
struct redraw_data {
	bool resize;
	string msg;
	string sender;
	WINDOW* win;
};
static deque<redraw_data> mq; /* messages and resizes yet to be drawn */
/* manage access to message queue: */
static pthread_mutex_t qmx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER;

/* XXX different colors for different senders */

/* record chat history as deque of strings: */
static deque<string> transcript;

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

int listensock, sockfd;

static bool should_exit = false;

// global variables for pks and sks
mpz_t global_client_pk;
mpz_t global_client_sk;
mpz_t global_server_pk;
mpz_t global_server_sk;

// global rsa keys
RSA* server_rsa_keys;
RSA* client_rsa_keys;

int global_encryptedMessageLen = 256;
int global_encodedMessageLen = 256;

// file paths
const char* CLIENT_PUBLIC_RSA_KEY_PATH = "clientPublicRSAKey.pem";
const char* SERVER_PUBLIC_RSA_KEY_PATH = "serverPublicRSAKey.pem";

const size_t klen = 128;
int base = 62; //why? idk. refer to https://gmplib.org/manual/I_002fO-of-Integers#I_002fO-of-Integers
bool isclient; //turned global for convienence
bool gotPK = false;
bool varification = false;
unsigned char kA[klen]; //client dhfinal
unsigned char kB[klen]; //server dhfinal

// HMAC globals
unsigned char clientMac[64]; // global variable to store computed HMAC
unsigned char serverMac[64]; // global variable to store computed HMAC

/**
 * Write a log message to a text file
 * @author Chenhao L.
*/
int log(const char* message, const char* filename = "log.txt") {
    
    // check to make sure file name exists
    FILE *logFile = fopen(filename, "r");
    if(logFile == NULL) {
        // create this file
        FILE *newLogFile = fopen(filename, "w");
        
        if(newLogFile == NULL)  {
            printf("Cannot create %s", filename); 
            return 1;
        }

        fprintf(newLogFile, "--Beginning of the log file--\n");

        fclose(newLogFile);
    } else fclose(logFile);

    // write to log file
    FILE *fp;
	fp = fopen(filename, "a");
	if(fp == NULL) {
        printf("Cannot open %s", filename);
		return 1; 
	}

	fprintf(fp, "%s\n", message);
	fclose(fp);

    return 0;
}

/**
 * Log the encrypted message in bytes to log.txt
 * @author Chenhao L.
*/
void logEncryptedMessage(unsigned char* encryptedMessage, size_t len) {
	log("Logging the encrypted message in bytes...");
	
	for(size_t i = 0; i < len; i++) {
		char* text = (char*)malloc(3 * sizeof(char));
		sprintf(text, "%02x", encryptedMessage[i]);
		log(text);
		free(text);
	}

	log("Finished logging the encrypted message in bytes");
}

/**
 * Log the encrypted message encoded in base64 to log.txt
 * @author Chenhao L.
*/
void logEncryptedMessage(const char* encryptedMessage) {
	log("Logging the encrypted message in base 64");
	log(encryptedMessage);
	log("Finished logging the encrypted message in base 64");
}

/**
 * Delete Server_dh and Client_dh files due to sync issues
 * @author Chenhao L.
*/
void deleteDHFiles() {
	if(access("Client_dh", W_OK) == 0) {
		remove("Client_dh");
	}

	if(access("Server_dh", W_OK) == 0) {
		remove("Server_dh");
	}
}


/**
 * Convert the encrypted bytes into base 64 to transfer across the channel
 * @param bytes - The encrypted bits
 * @param len - the size of the bits
 * @return the encrypted message encoded in base64 
 * @author Chenhao L.
*/
char* convertBytesToBase64(unsigned char* bytes, size_t len) {
	// encode the string into base64
	BIO* bio = BIO_new(BIO_s_mem());
	BIO* base64 = BIO_new(BIO_f_base64());

	// i dont understand any of this but it works
	BIO_push(base64, bio);
	BIO_write(base64, bytes, len);
	BIO_flush(base64);

	BUF_MEM* mem = NULL;
	BIO_get_mem_ptr(bio, &mem);
	char* base64EncodedMessage = (char*)malloc(mem->length + 1);
	memcpy(base64EncodedMessage, mem->data, mem->length);
	base64EncodedMessage[mem->length] = '\0';
	BIO_free_all(base64);

	return base64EncodedMessage;
}

/**
 * Convert the base64 encoded message back into encrypted bytes
 * @param encodedMessage - the base64 encoded message
 * @return the encrypted message in bytes
 * @author Chenhao L.
*/
unsigned char* convertBase64ToBytes(const char* encodedMessage) {
	size_t encodedMessage_len = strlen(encodedMessage);

	// decode the encoded b64 string back into bytes
	BIO* bio = BIO_new_mem_buf(encodedMessage, encodedMessage_len);
	BIO* base64 = BIO_new(BIO_f_base64());
	BIO_push(base64, bio);

	unsigned char* encodedMessageInBytes = (unsigned char*)malloc(global_encryptedMessageLen * sizeof(char));
	BIO_read(base64, encodedMessageInBytes, encodedMessage_len);
	BIO_free_all(base64);

	return encodedMessageInBytes;
}

/**
 * Generate a RSA using the boiler plate code provide in openssl-examples
 * @return a new RSA key
*/
RSA* generateRSAKeys() {
	RSA* keys = RSA_new();
	if (!keys) exit(1);
	BIGNUM* e = BN_new();
	if (!e) exit(1);
	BN_set_word(e,RSA_F4); /* e = 65537  */
	/* NOTE: if you have an old enough openssl library, you might
	 * have to setup the random number generator before this call: */
	int r = RSA_generate_key_ex(keys,2048,e,NULL);
	if (r != 1) exit(1);

	return keys;
}

/**
 * Encrypt the incoming message with RSA encryption
 * @param message - the message to encrypt
 * @return the message encrypted using RSA and encoded in base64
 * @author Chenhao L.
*/
char* encryptMessage(const char* message) {

	const char* otherUserPublicKeyPath = isclient ? SERVER_PUBLIC_RSA_KEY_PATH : CLIENT_PUBLIC_RSA_KEY_PATH;

	// read pk
	FILE* fs = fopen(otherUserPublicKeyPath, "r");
	if(fs == NULL) exit(1);

	RSA* otherUserRSAPublicKey = PEM_read_RSA_PUBKEY(fs, NULL, NULL, NULL);

	// encrypt using the other user's pk
	size_t len = strlen(message);
	unsigned char* encryptedMessage = (unsigned char*)malloc(RSA_size(otherUserRSAPublicKey));
	int encryptedMessageLen = RSA_public_encrypt(len+1, (unsigned char*)message, encryptedMessage, otherUserRSAPublicKey, RSA_PKCS1_OAEP_PADDING);
	if (encryptedMessageLen == -1) exit(1);

	fclose(fs);

	global_encryptedMessageLen = encryptedMessageLen;

	// encode into base64
	return convertBytesToBase64(encryptedMessage, encryptedMessageLen);
}

/**
 * Decrypt the incoming message
 * @param encodedMessage - the incoming message from the other user
 * @return the decrypted message in plain text
 * @author Chenhao L.
*/
char* decryptMessage(const char* encodedMessage) {
	// decrypt the base64 encoded msg
	unsigned char* encryptedMessageInBytes = convertBase64ToBytes(encodedMessage);

	// decrypt the encrytion by using the user's private key
	RSA* keys = isclient ? client_rsa_keys : server_rsa_keys;

	char* pt = (char*)malloc(global_encryptedMessageLen * sizeof(char));
	size_t ptlen = RSA_private_decrypt(global_encryptedMessageLen, encryptedMessageInBytes,(unsigned char*)pt,keys, RSA_PKCS1_OAEP_PADDING);

	if(ptlen == -1) {
		should_exit = true;
		exit(1);
	}

	return pt;
}

[[noreturn]] static void fail_exit(const char *msg);

[[noreturn]] static void error(const char *msg)
{
	perror(msg);
	fail_exit("");
}

// HMAC helpers
// This is for computing HMAC for client
void hmacClient(const char* message)
{	
    // convert mpz_t to char
    // get the size of the buffer needed to hold the string
    size_t size = mpz_sizeinbase(global_client_sk, 10) + 2;  // +2 for sign and null terminator
    // allocate a buffer to hold the string representation
    char* buffer = new char[size];
    // convert global_client_sk to a string
    mpz_get_str(buffer, 10, global_client_sk);
    // create a std::string from the buffer
    std::string stringClientKey(buffer);
    // free the buffer
    delete[] buffer;
    
    // HMAC
    const char* hmackey = stringClientKey.c_str();
    unsigned char mac[64]; /* if using sha512 */
    memset(mac, 0, sizeof(mac));
    HMAC(EVP_sha512(), hmackey, strlen(hmackey), (unsigned char*)message, strlen(message), mac, 0);

	// store HMAC
    memcpy(clientMac, mac, sizeof(mac));
}
//This is to compute HMAC for server
void hmacServer(const char* message)
{
    // convert mpz_t to char
    // get the size of the buffer needed to hold the string
    size_t size = mpz_sizeinbase(global_server_sk, 10) + 2;  // +2 for sign and null terminator
    // allocate a buffer to hold the string representation
    char* buffer = new char[size];
    // convert global_client_sk to a string
    mpz_get_str(buffer, 10, global_server_sk);
    // create a std::string from the buffer
    std::string stringServerKey(buffer);
    // free the buffer
    delete[] buffer;
    
    // HMAC
    const char* hmackey = stringServerKey.c_str();
    unsigned char mac[64]; /* if using sha512 */
    memset(mac, 0, sizeof(mac));
    HMAC(EVP_sha512(), hmackey, strlen(hmackey), (unsigned char*)message, strlen(message), mac,0);

	// store HMAC
    memcpy(serverMac, mac, sizeof(mac));
}

// required handshake with the client
int initServerNet(int port)
{
	deleteDHFiles();

	if (init("params") != 0) {
		log("initServerNet: Cannot init Diffie Hellman key exchange :(");
		printf("Cannot init Diffie Hellman key exchange :(");
		// exit the program
		should_exit = true;
	}

	// generate Server public key
	NEWZ(global_server_sk);
	NEWZ(global_server_pk);
	NEWZ(global_client_pk);
	if(dhGen(global_server_sk, global_server_pk) != 0) {
		log("Something went wrong in dhGen() on the server, did you run the init() function?");

		// instead of shutting down the program when keys cannot be generated, in the future
		// there should be a feature that informs both users that the chat is not encrypted and unsecured
		// - Chenhao L.

		// exit the program
		should_exit = true;
		exit(-1);
	}
	//store Server public key (g^a mod p) to file "PublicKeyServer". 
	FILE *pk2 = fopen("PublicKeyServer", "w");
	mpz_out_str(pk2, base, global_server_pk);
	fclose(pk2);

	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	else
	{
		// size_t SERVER_SIZE = mpz_sizeinbase(global_server_pk, base);
		// unsigned long a[SERVER_SIZE];
		// BYTES2Z(global_server_pk, a, SERVER_SIZE);
		// size_t a_size = sizeof(a);
		// printf("SIZE OF A: %ld\nSERVER_SIZE: %d\n", sizeof(a), SERVER_SIZE); // >5000

		// if(send(sockfd, &SERVER_SIZE, sizeof(SERVER_SIZE), 0) < 0) //doesnt work with SERVER_SIZE either
		// 	perror("send");
		// if(send(sockfd, a, a_size, 0) < 0)
		// 	perror("send");

		// printf("%llu\n", a);


		//CALCULATE SIZE OF SERVER PK
		size_t SERVER_SIZE = mpz_sizeinbase(global_server_pk, base);
		//SENDING SIZE OF SERVER PK
		if(send(sockfd, &SERVER_SIZE, sizeof(SERVER_SIZE), 0) < 0)
			perror("send");

		char server_pk[SERVER_SIZE];
		mpz_get_str(server_pk, base, global_server_pk); //convert to string
 		
 		//send server_pk
		if(send(sockfd, server_pk, SERVER_SIZE, 0) < 0)
		{
			// perror("send");
			printf("Error sending server_pk: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
		{
			printf("Sent server_pk successful\n");
		}


		// //RECEIVING CLIENT PK
		size_t CLIENT_SIZE;
		if(recv(sockfd, &CLIENT_SIZE, sizeof(CLIENT_SIZE), 0) < 0)
				perror("recv");

		char client_pk[CLIENT_SIZE];
		if(recv(sockfd, client_pk, CLIENT_SIZE, 0) < 0) //recv client_pk
		{
			printf("Error receiving client_pk: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
		{
			printf("Received client_pk successful\n");
			mpz_set_str(global_client_pk, client_pk, base);
		}

		//Print output for size and pk
		// printf("SERVER SIZE: %d\n", sizeof(server_pk));
		// printf("CLIENT Size: %d\n", sizeof(client_pk));

		// printf("Server_pk\n%s\nClient_pk\n%s\n", server_pk, client_pk);
		
		dhFinal(global_server_sk,global_server_pk,global_client_pk,kB,klen); //create dhfinal

		// printf("SERVER DHFINAL\n");
		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kB[i]);
		// }								

		//Sending SERVER DHFinal
		if(send(sockfd, kB, sizeof(kB), 0) < 0) 
		{
			printf("Error sending server_dhf: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
			printf("Sent server_dhf successful\n");

		//Receiving CLIENT DHFinal
		if(recv(sockfd, kA, sizeof(kA), 0) < 0) 
		{
			printf("Error receiving client_dhf: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
			printf("Received client_dhf successful\n");

		// printf("Client's key:\n");
		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kA[i]);
		// }

		if (memcmp(kB,kA,klen) != 0)
		{
			printf("No match\n");
			exit(-1);
		}
		else
			printf("DHfinal keys match\n");

		memset(kA, 0, sizeof(kA)); //erase information

		// generate RSA key for the server
		server_rsa_keys = generateRSAKeys();

<<<<<<< HEAD
=======



		// while(access("PublicKeyClient", F_OK) != 0) {
		// 	sleep(1);
		// }

		// //Get client public key
		// FILE *pk1 = fopen("PublicKeyClient", "r");
		// if(pk1 == NULL) {
		// 	error("Cannot read client dh key :(");
		// 	exit(1);
		// }

		// mpz_inp_str(global_client_pk, pk1, base);
		// fclose(pk1);

		// dhFinal(global_server_sk,global_server_pk,global_client_pk,kB,klen);


		// FILE *Server_dh = fopen("Server_dh", "wb"); //write in binary format
		// size_t r1 = fwrite(kB, sizeof kB[0], klen, Server_dh);
		// if(r1 < 0)
		// {
		// 	perror("fwrite");
		// 	exit(-1);
		// }
		// fclose(Server_dh);

		// unsigned char kC[klen];

		// // wait until the client dh_key has been fully created
		// // i know this is bad code but it works - Chenhao
		// while(access("Client_dh", F_OK) != 0) {
		// 	sleep(1);
		// }

		// FILE *Client_dh = fopen("Client_dh", "rb"); 
		// if(Client_dh == NULL) {
		// 	error("Cannot read client dh bytes :(");
		// 	exit(1);
		// }

		// size_t r2 = fread(kC, sizeof kC[0], klen, Client_dh);
		// if(r2 < 0)
		// {
		// 	perror("fwrite");
		// 	exit(-1);
		// }		
		// fclose(Client_dh);


		// if (memcmp(kB,kC,klen) != 0)
		// {
		// 	printf("\nError: Client did not match server dh\n");
		// 	printf("\nServer SH\n");
		// 	for (size_t i = 0; i < klen; i++) {
		// 		printf("%02x ",kB[i]);
		// 	}
		// 	printf("\nClient SH\n");
		// 	for (size_t i = 0; i < klen; i++) {
		// 		printf("%02x ",kC[i]);
		// 	}
		// 	// should_exit = true;
		// 	printf("\n");
		// 	exit(-1);
		// }

		// memset(kC, 0, sizeof(kC)); //erase information


		// generate RSA key for the server
		server_rsa_keys = generateRSAKeys();

>>>>>>> d01a4988d6883b6d5e100e904a24a583a54202f1
		// write the public key to file
		FILE* serverPublicRSAKeyFs = fopen(SERVER_PUBLIC_RSA_KEY_PATH, "w");
		if(serverPublicRSAKeyFs == NULL) exit(1);
		PEM_write_RSA_PUBKEY(serverPublicRSAKeyFs, server_rsa_keys);
		fclose(serverPublicRSAKeyFs);
		
	}
	close(listensock);

	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	log("initServerNet: Successfully connected to server");

	return 0;
}

// required handshake with the sever
static int initClientNet(char* hostname, int port)
{
	if (init("params") != 0) {
		log("initClientNet: Cannot init Diffie Hellman key exchange :(");
		printf("Cannot init Diffie Hellman key exchange :(");
		// exit the program
		// should_exit = true;
		exit(-1);
	}


	// generate Client key
	NEWZ(global_client_sk);
	NEWZ(global_client_pk);
	NEWZ(global_server_pk);
	if(dhGen(global_client_sk, global_client_pk) != 0) {
		log("Something went wrong in dhGen() on the client, did you run init() function?");

		// should_exit = true;
		exit(-1);
	}

	//store Client public key (g^b mod p) to file "PublicKeyClient". 
	FILE *pk1 = fopen("PublicKeyClient", "w");
	mpz_out_str(pk1, base, global_client_pk);
	fclose(pk1);

	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	else
	{
		// size_t SERVER_SIZE;
		// if(recv(sockfd, &SERVER_SIZE, sizeof(SERVER_SIZE), 0) < 0)
		// 	perror("recv");

		// unsigned long a[SERVER_SIZE];

		// if(recv(sockfd, a, SERVER_SIZE, 0) < 0)
		// 	perror("recv");
		// printf("SIZE Of A: %d\nSERVER_SIZE: %ld\n",sizeof(a), SERVER_SIZE); //data coming in does not match
		// printf("%llu\n", a);
		// Z2BYTES(a,SERVER_SIZE,global_server_pk);


		//RECEIVE SIZE OF SERVER PK
		size_t SERVER_SIZE;
		if(recv(sockfd, &SERVER_SIZE, sizeof(SERVER_SIZE), 0) < 0)
			perror("recv");
		
		// Receiving SERVER PK
		char server_pk[SERVER_SIZE];
		if(recv(sockfd, server_pk, SERVER_SIZE, 0) < 0) //recv server_pk
		{	
			printf("Error receiving server_pk: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
		{
			printf("Received server_pk successful\n");
			mpz_set_str(global_server_pk, server_pk, base);
		}

		//Calculating size of CLIENT PK
		size_t CLIENT_SIZE = mpz_sizeinbase(global_client_pk, base);
		if(send(sockfd, &CLIENT_SIZE, sizeof(CLIENT_SIZE), 0) < 0)
			perror("send");

		char client_pk[CLIENT_SIZE];
		mpz_get_str(client_pk, base, global_client_pk); //convert to string

		//send client_pk
		if(send(sockfd, client_pk, CLIENT_SIZE, 0) < 0) 
		{
			printf("Error sending client_pk: [%s]\n", strerror(errno));
			exit(-1);
		}	
		else
		{
			printf("Sent client_pk successful\n");
		}

		//Print output for size and pk
		// printf("Client Size: %d\n", sizeof(client_pk));
		// printf("SERVER Size: %d\n", sizeof(server_pk));

		// printf("Client_pk\n%s\nServer_pk\n%s\n", client_pk, server_pk);

		// //Generate DHFINAL
		// printf("CLIENT DHFINAL\n");
		dhFinal(global_client_sk,global_client_pk,global_server_pk,kA,klen); //create dhfinal

		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kA[i]);
		// }

		//Receiving SERVER DHFinal
		if(recv(sockfd, kB, sizeof(kB), 0) < 0) 
		{
			printf("Error receiving server_dhf: [%s]\n", strerror(errno));
			exit(-1);
		}
		else
			printf("Received server_dhf successful\n");
		
		// printf("SERVER's key:\n");
		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kA[i]);
		// }

<<<<<<< HEAD
		// Sending CLIENT DHFinal
		if(send(sockfd, kA, sizeof(kA), 0) < 0) 
		{
			printf("Error sending client_dhf: [%s]\n", strerror(errno));
			// perror("send");
			exit(-1);
		}
		else
			printf("Sent client_dhf successful\n");

		if (memcmp(kA,kB,klen) != 0)
		{
			printf("No match\n");
			exit(-1);
		}
		else
			printf("DHfinal keys match\n");

		memset(kB, 0, sizeof(kB)); //erase information
=======



		
		// while(access("PublicKeyServer", F_OK) != 0) {
		// 	sleep(1);
		// }

		// //read from file to get Server public key
		// FILE *pk2 = fopen("PublicKeyServer", "r");
		// if(pk2 == NULL) {
		// 	error("Cannot read server dh key :(");
		// 	exit(1);
		// }

		// mpz_inp_str(global_server_pk, pk2, base);
		// fclose(pk2);

		// //Get DH
		// dhFinal(global_client_sk,global_client_pk,global_server_pk,kA,klen);
		// // for (size_t i = 0; i < klen; i++) {
		// // 	printf("%02x ",kA[i]);
		// // }

		// logEncryptedMessage(kA, 128);

		// //write to file ClientDH in binary format
		// FILE *Client_dh = fopen("Client_dh", "wb"); 
		// size_t r1 = fwrite(kA, sizeof kA[0], klen, Client_dh);
		// if(r1 < 0)
		// {
		// 	perror("fwrite");
		// 	exit(-1);
		// }

		// fflush(Client_dh);
		// fclose(Client_dh);

		// unsigned char kC[klen];

		// while(access("Server_dh", F_OK) != 0) {
		// 	sleep(1);
		// }
		
		// FILE *Server_dh = fopen("Server_dh", "rb");
		// if(Server_dh == NULL) {
		// 	error("Cannot read server dh bytes :(");
		// 	exit(1);
		// } 

		// size_t r2 = fread(kC, sizeof kC[0], klen, Server_dh);
		// if(r2 < 0)
		// {
		// 	perror("fwrite");
		// 	exit(-1);
		// }
		// fclose(Server_dh);

		// if (memcmp(kA,kC,klen) != 0)
		// {
		// 	sleep(1);

		// 	//Client is weird
		// 	while(access("Server_dh", F_OK) != 0) {
		// 		sleep(1);
		// 	}

		// 	FILE *Server_dh = fopen("Server_dh", "rb"); 
		// 	size_t r2 = fread(kC, sizeof kC[0], klen, Server_dh);
		// 	if(r2 < 0)
		// 	{
		// 		perror("fwrite");
		// 		exit(-1);
		// 	}
		// 	fclose(Server_dh);
			
		// 	if (memcmp(kA,kC,klen) != 0)
		// 	{
		// 		printf("\nError: Server did not match client dh\n");
		// 		printf("Client SH\n");
		// 			for (size_t i = 0; i < klen; i++) {
		// 			printf("%02x ",kA[i]);
		// 		}
		// 		printf("\nServer SH\n");
		// 		for (size_t i = 0; i < klen; i++) {
		// 			printf("%02x ",kC[i]);
		// 		}	
		// 		// should_exit = true;
		// 		printf("\n");
		// 		exit(-1);
		// 	}
		// }
		// memset(kC, 0, sizeof(kC)); //erase information
>>>>>>> d01a4988d6883b6d5e100e904a24a583a54202f1

		// generate RSA key for the client
		client_rsa_keys = generateRSAKeys();

		// write the public key to file
		FILE* clientPublicRSAKeyFs = fopen(CLIENT_PUBLIC_RSA_KEY_PATH, "w");
		if(clientPublicRSAKeyFs == NULL) exit(1);
		PEM_write_RSA_PUBKEY(clientPublicRSAKeyFs, client_rsa_keys);
		fclose(clientPublicRSAKeyFs);

	}
	/* at this point, should be able to send/recv on sockfd */

	// connection successful with the client and server
	log("initClientNet: Successfully connected to client");

	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


[[noreturn]] static void fail_exit(const char *msg)
{
	// Make sure endwin() is only called in visual mode. As a note, calling it
	// twice does not seem to be supported and messed with the cursor position.
	if (!isendwin())
		endwin();
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

// Checks errors for (most) ncurses functions. CHECK(fn, x, y, z) is a checked
// version of fn(x, y, z).
#define CHECK(fn, ...) \
	do \
	if (fn(__VA_ARGS__) == ERR) \
	fail_exit(#fn"("#__VA_ARGS__") failed"); \
	while (false)


// Message window
static WINDOW *msg_win;
// Separator line above the command (readline) window
static WINDOW *sep_win;
// Command (readline) window
static WINDOW *cmd_win;

// Input character for readline
static unsigned char input;

static int readline_getc(FILE *dummy)
{
	return input;
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void msg_win_redisplay(bool batch, const string& newmsg="", const string& sender="")
{
	if (batch)
		wnoutrefresh(msg_win);
	else {
		wattron(msg_win,COLOR_PAIR(2));
		wprintw(msg_win,"%s:",sender.c_str());
		wattroff(msg_win,COLOR_PAIR(2));
		wprintw(msg_win," %s\n",newmsg.c_str());
		wrefresh(msg_win);
	}
}

static void msg_typed(char *line)
{ 
	if(isclient && !gotPK)
	{
		//read from file to get other persons public key 2.
		FILE *pk2 = fopen("PublicKeyServer", "r");
		mpz_inp_str(global_server_pk, pk2, base);
		fclose(pk2);
		gotPK = true;
		//Get DH
		dhFinal(global_client_sk,global_client_pk,global_server_pk,kA,klen);
		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kA[i]);
		// }

		//check if they got correct pk
		FILE *DH1 = fopen("DH1-PK2", "w");
		mpz_out_str(DH1, base, global_server_pk);
		fclose(DH1);
		// verified: received correct pk
	}
	else if (!isclient && !gotPK)
	{
		//read from file to get other persons public key 1.
		FILE *pk1 = fopen("PublicKeyClient", "r");
		mpz_inp_str(global_client_pk, pk1, base);
		fclose(pk1);
		gotPK = true;
		dhFinal(global_server_sk,global_server_pk,global_client_pk,kB,klen);
		// for (size_t i = 0; i < klen; i++) {
		// 	printf("%02x ",kB[i]);
		// }

		//check if they got correct pk
		FILE *DH2 = fopen("DH2-PK1", "w");
		mpz_out_str(DH2, base, global_client_pk);
		fclose(DH2); 
		//verified: received correct pk
	}

	// If client and DH is calculated then we can do HMAC
	if (isclient && gotPK){
		hmacClient(line);
	// Esle we do server when DH is calculated, then we do HMAC
	} else if (!isclient && gotPK){
		hmacServer(line);
	}

	string line_str;
	if (!line) {
		// Ctrl-D pressed on empty line
		should_exit = true;
		/* XXX send a "goodbye" message so other end doesn't
		 * have to wait for timeout on recv()? */
	} else {
		if (*line) {
			char* encrypted_line = encryptMessage(line);

			add_history(encrypted_line);

			global_encodedMessageLen = strlen(encrypted_line);
			line_str = string(line);
			
			transcript.push_back("me: " + line_str);

			ssize_t nbytes;
			if ((nbytes = send(sockfd,encrypted_line, global_encodedMessageLen,0)) == -1)
				error("send failed");
		}
		pthread_mutex_lock(&qmx);
		mq.push_back({false,line_str,"me",msg_win});
		pthread_cond_signal(&qcv);
		pthread_mutex_unlock(&qmx);
	}
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void cmd_win_redisplay(bool batch)
{
	int prompt_width = strnlen(rl_display_prompt, 128);
	int cursor_col = prompt_width + strnlen(rl_line_buffer,rl_point);

	werase(cmd_win);
	mvwprintw(cmd_win, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
	/* XXX deal with a longer message than the terminal window can show */
	if (cursor_col >= COLS) {
		// Hide the cursor if it lies outside the window. Otherwise it'll
		// appear on the very right.
		curs_set(0);
	} else {
		wmove(cmd_win,0,cursor_col);
		curs_set(1);
	}
	if (batch)
		wnoutrefresh(cmd_win);
	else
		wrefresh(cmd_win);
}

static void readline_redisplay(void)
{
	pthread_mutex_lock(&qmx);
	mq.push_back({false,"","",cmd_win});
	pthread_cond_signal(&qcv);
	pthread_mutex_unlock(&qmx);
}

static void resize(void)
{
	if (LINES >= 3) {
		wresize(msg_win,LINES-2,COLS);
		wresize(sep_win,1,COLS);
		wresize(cmd_win,1,COLS);
		/* now move bottom two to last lines: */
		mvwin(sep_win,LINES-2,0);
		mvwin(cmd_win,LINES-1,0);
	}

	/* Batch refreshes and commit them with doupdate() */
	msg_win_redisplay(true);
	wnoutrefresh(sep_win);
	cmd_win_redisplay(true);
	doupdate();
}

static void init_ncurses(void)
{
	if (!initscr())
		fail_exit("Failed to initialize ncurses");

	if (has_colors()) {
		CHECK(start_color);
		CHECK(use_default_colors);
	}
	CHECK(cbreak);
	CHECK(noecho);
	CHECK(nonl);
	CHECK(intrflush, NULL, FALSE);

	curs_set(1);

	if (LINES >= 3) {
		msg_win = newwin(LINES - 2, COLS, 0, 0);
		sep_win = newwin(1, COLS, LINES - 2, 0);
		cmd_win = newwin(1, COLS, LINES - 1, 0);
	} else {
		// Degenerate case. Give the windows the minimum workable size to
		// prevent errors from e.g. wmove().
		msg_win = newwin(1, COLS, 0, 0);
		sep_win = newwin(1, COLS, 0, 0);
		cmd_win = newwin(1, COLS, 0, 0);
	}
	if (!msg_win || !sep_win || !cmd_win)
		fail_exit("Failed to allocate windows");

	scrollok(msg_win,true);

	if (has_colors()) {
		// Use white-on-blue cells for the separator window...
		CHECK(init_pair, 1, COLOR_WHITE, COLOR_BLUE);
		CHECK(wbkgd, sep_win, COLOR_PAIR(1));
		/* NOTE: -1 is the default background color, which for me does
		 * not appear to be any of the normal colors curses defines. */
		CHECK(init_pair, 2, COLOR_MAGENTA, -1);
	}
	else {
		wbkgd(sep_win,A_STANDOUT); /* c.f. man curs_attr */
	}
	wrefresh(sep_win);
}

static void deinit_ncurses(void)
{
	delwin(msg_win);
	delwin(sep_win);
	delwin(cmd_win);
	endwin();
}

static void init_readline(void)
{
	// Let ncurses do all terminal and signal handling
	rl_catch_signals = 0;
	rl_catch_sigwinch = 0;
	rl_deprep_term_function = NULL;
	rl_prep_term_function = NULL;

	// Prevent readline from setting the LINES and COLUMNS environment
	// variables, which override dynamic size adjustments in ncurses. When
	// using the alternate readline interface (as we do here), LINES and
	// COLUMNS are not updated if the terminal is resized between two calls to
	// rl_callback_read_char() (which is almost always the case).
	rl_change_environment = 0;

	// Handle input by manually feeding characters to readline
	rl_getc_function = readline_getc;
	rl_redisplay_function = readline_redisplay;

	rl_callback_handler_install("> ", msg_typed);
}

static void deinit_readline(void)
{
	rl_callback_handler_remove();
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat for CSc380.\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

int main(int argc, char *argv[])
{
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;
	// bool isclient = true;
	isclient = true;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = false;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* NOTE: these don't work if called from cursesthread */
	init_ncurses();
	init_readline();
	/* start curses thread */
	if (pthread_create(&tcurses,0,cursesthread,0)) {
		fprintf(stderr, "Failed to create curses thread.\n");
	}
	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	/* put this in the queue to signal need for resize: */
	redraw_data rd = {false,"","",NULL};
	do {
		int c = wgetch(cmd_win);
		switch (c) {
			case KEY_RESIZE:
				pthread_mutex_lock(&qmx);
				mq.push_back(rd);
				pthread_cond_signal(&qcv);
				pthread_mutex_unlock(&qmx);
				break;
				// Ctrl-L -- redraw screen
			// case '\f':m
			// 	// Makes the next refresh repaint the screen from scratch
			// 	/* XXX this needs to be done in the curses thread as well. */
			// 	clearok(curscr,true);
			// 	resize();
			// 	break;
			default:
				input = c;
				rl_callback_read_char();
		}
	} while (!should_exit);

	shutdownNetwork();
	deinit_ncurses();
	deinit_readline();
	return 0;
}

/* Let's have one thread responsible for all things curses.  It should
 * 1. Initialize the library
 * 2. Wait for messages (we'll need a mutex-protected queue)
 * 3. Restore terminal / end curses mode? */

/* We'll need yet another thread to listen for incoming messages and
 * post them to the queue. */

void* cursesthread(void* pData)
{
	/* NOTE: these calls only worked from the main thread... */
	// init_ncurses();
	// init_readline();
	while (true) {
		pthread_mutex_lock(&qmx);
		while (mq.empty()) {
			pthread_cond_wait(&qcv,&qmx);
			/* NOTE: pthread_cond_wait will release the mutex and block, then
			 * reaquire it before returning.  Given that only one thread (this
			 * one) consumes elements of the queue, we probably don't have to
			 * check in a loop like this, but in general this is the recommended
			 * way to do it.  See the man page for details. */
		}
		/* at this point, we have control of the queue, which is not empty,
		 * so write all the messages and then let go of the mutex. */
		while (!mq.empty()) {
			redraw_data m = mq.front();
			mq.pop_front();
			if (m.win == cmd_win) {
				cmd_win_redisplay(m.resize);
			} else if (m.resize) {
				resize();
			} else {
				msg_win_redisplay(false,m.msg,m.sender);
				/* Redraw input window to "focus" it (otherwise the cursor
				 * will appear in the transcript which is confusing). */
				cmd_win_redisplay(false);
			}
		}
		pthread_mutex_unlock(&qmx);
	}
	return 0;
}

void* recvMsg(void*)
{
	// since we need to get the encoded message, the original 256 bit was too small
	// hopefully 1024 is big enough :/ - Chenhao L.
	const int BUFFER_SIZE = 1024;

	char* msg = (char*)malloc(BUFFER_SIZE * sizeof(char));
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,BUFFER_SIZE,0)) == -1)
			error("recv failed");
		msg[nbytes] = 0; /* make sure it is null-terminated */
		if (nbytes == 0) {
			/* signal to the main loop that we should quit: */
			should_exit = true;
			return 0;
		} 

		// decrypt the message here
		char* decryptedMessage = decryptMessage(msg);

        // HMAC
        //    If client and DH is calculated then we can do HMAC
        if (isclient && gotPK){
			hmacServer(decryptedMessage);
            
            // Server should already be computed
            if (clientMac == serverMac) {
                // send "authentication success"
            } else {
                // send "authentication failed"
            }

        // Esle we do server when DH is calculated, then we do HMAC
        } else if (!isclient && gotPK){
            hmacClient(decryptedMessage);

            // client should already be computed
            if (clientMac == serverMac) {
                // send "authentication success"
            } else {
                // send "authentication failed"
            }
        }

		pthread_mutex_lock(&qmx);
		mq.push_back({false,decryptedMessage,"Mr Thread",msg_win});
		pthread_cond_signal(&qcv);
		pthread_mutex_unlock(&qmx);
	}
	
	return 0;
}