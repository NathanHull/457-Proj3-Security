#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
	EVP_PKEY_CTX *ctx;
	size_t outlen;
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!ctx)
		handleErrors();
	if (EVP_PKEY_encrypt_init(ctx) <= 0)
		handleErrors();
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		handleErrors();
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
		handleErrors();
	if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
		handleErrors();
	return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
		unsigned char *iv, unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		unsigned char *iv, unsigned char *plaintext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

int main(int argc, char** argv){
	int sockfd = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(sockfd<0){
		printf("There was an error creating the socket\n");
		return 1;
	}
	printf("Input desired IP\n");
	char ip[12];
	strcpy(ip, "127.0.0.1");
	//scanf("%s", ip);
	//getchar();

	printf("Input desired port\n");
	int port;
	port = 9898;
	//scanf("%i", &port);
	//getchar();

	printf("\nCommands:\n/quit - terminate client\n/list - list all connected users\n/message [user] [message] - send private [message] to [user]\n\n");

	fd_set sockets;
	FD_ZERO(&sockets);
	FD_SET(sockfd, &sockets);
	FD_SET(fileno(stdin), &sockets);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=inet_addr(ip);

	if (connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr)) < 0) {
		perror("There was an error connecting\n");
		return 1;
	}




	// Encryption
	unsigned char *pubfile = "RSApub.pem";
	unsigned char key[32];
	unsigned char encryptedkey[256];
	int ciphertext_len, encryptedkey_len;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	// Generate symmetric key
	RAND_bytes(key, 32);
	EVP_PKEY *pubkey;
	printf("Generated symmetric key: %s\n", key);

	// Encrypt symmetric key via RSA public key
	FILE* pubf = fopen(pubfile, "rb");
	pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
	encryptedkey_len = rsa_encrypt(key, 32, pubkey, encryptedkey);
	printf("Encrypted symmetric key: %s\n", encryptedkey);

	// Encrypt key
	send(sockfd, encryptedkey, encryptedkey_len, 0);
	printf("Key sent\n");




	while (1) {
		fd_set tmp_set = sockets;
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
		int i;

		for (i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &tmp_set)) {
				if (i == sockfd) {
				printf("FIRST\n");
					unsigned char status[33];
					unsigned char message[1024];
					unsigned char decryptedStatus[25];
					unsigned char decryptedMessage[1024];
					unsigned char iv[16];

					recv(i, status, 33, 0);
					if (strlen(status) == 0) {
						continue;
					}
					printf("MESSAGE: |%s|\n", status);

					// Decrypt status
					strncpy(iv, status, 16);
					decrypt(status, strlen(status), key, iv, decryptedStatus);
					printf("Received IV: %s\n", iv);
					printf("%s ", status+16);

					if (strncmp(status, "/quit", 5) == 0) {
						printf ("Quitting\n");
						close(i);
						FD_CLR(i, &sockets);

						EVP_cleanup();
						ERR_free_strings();
						return 0;
					}

					recv(i, message, 1024, 0);
					printf("%s\n", message);
				}

				else if (i == fileno(stdin)) {
					// Generate random initialization vector to ensure different encryption for identical messages
					printf("BEFORE\n");
					unsigned char iv[16];
					RAND_bytes(iv, 16);
					printf("AFTER\n");

					unsigned char encryptedMessage[1024];
					int encryptedMessage_len;
					unsigned char message[1024];

					strncpy(message, iv, 16);
					fgets(message+16, 1024, stdin);

					// Encrypt message
					encryptedMessage_len = encrypt(message+16, strlen((char*) message), key, iv, encryptedMessage);
					printf("Encrypted message: %s\n", encryptedMessage);

					send(sockfd, message, sizeof(encryptedMessage), 0);

					if (strcmp(message, "/quit\n") == 0) {
						close(sockfd);
						FD_CLR(sockfd, &sockets);
						printf("Quitting\n");

						EVP_cleanup();
						ERR_free_strings();
						return 0;
					}

					printf("\n");
				}
			}

		}
	}
	close(sockfd);
	return 0;
}
