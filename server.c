#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

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

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
	EVP_PKEY_CTX *ctx;
	size_t outlen;
	ctx = EVP_PKEY_CTX_new(key,NULL);
	if (!ctx)
		handleErrors();
	if (EVP_PKEY_decrypt_init(ctx) <= 0)
		handleErrors();
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		handleErrors();
	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
		handleErrors();
	if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
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

int main(int argc, char **argv){
	int sockfd = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
	int enable = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	int users[10];
	unsigned char keys[10][32];
	int numUsers = 0;

	fd_set sockets; //fd stands for file descriptor
	FD_ZERO(&sockets);

	//printf("Input desired port\n");
	//char temp[6];
	//fgets(temp, sizeof(temp), stdin);
	//int port = atoi(temp);
	int port = 9898;
	printf("Sock on port %i\n", port);

	printf("\nCommands:\n/quit - terminate server\n/list - list all connected users\n/message [user] [message] - send private [message] to [user]\n/kick [user] - kick [user] from the server\n\n");

	struct sockaddr_in serveraddr,clientaddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=INADDR_ANY;

	bind(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	listen(sockfd,10);

	FD_SET(sockfd, &sockets);  //put sockfd into sockets set
	FD_SET(fileno(stdin), &sockets);

	int len=sizeof(clientaddr);
	int clientsocket;
	int i;
	int x;

	for (x = 0; x < 10; x++) {
		users[x] = -1;
	}

	


	// =====================================================
	// Set up encryption
	// =====================================================
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	EVP_PKEY *privkey;
	unsigned char *privfilename = "RSApriv.pem";
	FILE* privf = fopen(privfilename, "rb");
	privkey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);

	while(1){
		// keep copy of original set before destructive operation select
		fd_set tmp_set = sockets;
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);

		for (i = 0; i < FD_SETSIZE; i++ ) {
			if (FD_ISSET(i, &tmp_set)) {

				// =====================================================
				// Add new client socket fd to users table
				// =====================================================
				if (i == sockfd) {
					clientsocket = accept(sockfd,(struct sockaddr*)&clientaddr,(socklen_t *)&len);
					FD_SET(clientsocket, &sockets); // every time I receive a client, also add it to the set

					users[numUsers] = clientsocket; 
					printf("Client %i connected\n", clientsocket);

					// Get key
					unsigned char encryptedkey[256];
					recv(clientsocket, encryptedkey, 256, 0);

					unsigned char decryptedkey[32];
					rsa_decrypt(encryptedkey, sizeof(encryptedkey), privkey, decryptedkey);
					printf("Decrypted key: %s\n", decryptedkey);
					strcpy(keys[numUsers], decryptedkey);
					
					numUsers++;
					printf("\n");




				// =====================================================
				// Handle server input
				// =====================================================
				} else if (i == fileno(stdin)) {
					unsigned char status[50];
					unsigned char line[256];
					fgets(line, sizeof(line), stdin);

					// handle commands
					if (line[0] == '/') {
						if (!strcmp(line, "/list\n")) {
							for (x = 0; x < FD_SETSIZE; x++) {
								if (FD_ISSET(x, &sockets) && x != fileno(stdin) && x != sockfd)
									printf("User: %i\n", x);
							}
							printf("\n");

						} else if (!strncmp(line, "/message", 8)) {
							int target = atoi((const char *) &line[9]);
							sprintf(status, "Private message from 0:");
							send(target, status, strlen(status), 0);
							send(target, line+10, strlen(line)-9, 0);

						} else if (!strncmp(line, "/kick", 5)) {
							int target = atoi((const char *) &line[6]);
							for (x = 0; x < numUsers; x++) {
								if (users[x] == target) {
									printf("Kicking user %i\n", users[x]);

									strcpy(line, "/quit\n\0");
									send(users[x], line, strlen(line), 0);

									FD_CLR(users[x], &sockets);
									close(users[x]);
									users[x] = -1;
								}
							}

						} else if (!strcmp(line, "/quit\n")) {
							printf("Shutting down server\n");

							// remove all FDs from set and exit
							for (x = 0; x < numUsers; x++) {
								if (users[x] != -1) {
									printf("Quit signal sent to %i\n", users[x]);
									send(users[x],line,strlen(line)+1,0);
								}
							}
							sleep(1);

							for (x = 0; x < FD_SETSIZE; x++) {
								if (FD_ISSET(x, &sockets)) {
									printf("Closing %i\n",x);
									FD_CLR(x, &sockets);
									close(x);
								}
							}

							// Cleanup openssl resources
							EVP_cleanup();
							ERR_free_strings();

							exit(0);

						} else {
							printf("Invalid command\n");
						}
					} else {
						// Send server message to all users
						strcpy(status, "Server Broadcast:");
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1) {
								send(users[x],status,sizeof(status),0);
								send(users[x],line,strlen(line)+1,0);
							}
						}
					}

					printf("\n");
				}




				// =====================================================
				// Handle client's message
				// =====================================================
				else {
					unsigned char status[50];
					unsigned char line[256];
					unsigned char decryptedMessage[256];
					unsigned char response[256];
					unsigned char encryptedResponse[256];
					unsigned char iv[16];

					recv(i,line,256,0);

					if(strlen(line) <= 0)
						continue;

					// Decrypt
					int index = 0;
					int len = line[16];
					for (x = 0; x < numUsers; x++) {
						if (users[x] == i) {
							index = x;
							break;
						}
					}
					memcpy(iv, line, 16);
					decrypt(line+17, len, keys[index], iv, decryptedMessage);
					line[len] = 0;
					printf("From client %i: %s\n",i,line+16);
					printf("Found IV: %s\n", iv);

					for (x = 0; x < strlen(decryptedMessage); x++) {
						if (decryptedMessage[x] == '\n') {
							decryptedMessage[x+1] = 0;
							break;
						}
					}
					printf("Decrypted message: %s\n", decryptedMessage);

					if (!strcmp(decryptedMessage,"/quit\n")) {
						printf("Client %i Quitting\n\n",i);

						// Omit user from table
						for (x = 0; x < numUsers; x++) {
							if (users[x] == i) {
								users[x] = -1;
								break;
							}
						}

						FD_CLR(i,&sockets);
						close(i);

					} else if (!strcmp(decryptedMessage, "/list\n")) {
						RAND_bytes(iv,16);
						printf("Generated IV: %s\n", iv);
						memcpy(status, iv, 16);
						strcpy(status+17, "Clients:");
						int curr = 0;
						int thisIndex = -1;

						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1) {
								response[curr] = '0' + users[x];
								curr++;
								response[curr] = ' ';
								curr++;
								if (users[x] == i)
									thisIndex = x;
							}
						}
						response[curr] = '\n';

						// encrypt list
						int len = encrypt(response, strlen(response), keys[thisIndex], iv, encryptedResponse);
						status[16] = len;

						send(i,status,sizeof(status),0);
						send(i,encryptedResponse,len,0);
						printf("List sent to user %i\n", i);
						printf("\n");

					} else if (!strncmp(decryptedMessage, "/message", 8)) {
						RAND_bytes(iv,16);
						printf("Generated IV: %s\n", iv);
						int target = atoi((const char *) &decryptedMessage[9]);
						int index = -1;
						unsigned char encryptedResponse[256];

						for (x = 0; x < numUsers; x++) {
							if (users[x] == target) {
								index = x;
								break;
							}
						}

						if(index == -1) {
							perror("FATAL ERROR\n");
						}

						sprintf(status+17, "Private msg from user %i:", i);

						int len = encrypt(decryptedMessage+11, strlen(decryptedMessage)-11, keys[index], iv, encryptedResponse);
						memcpy(status, iv, 16);
						status[16] = len;

						send(target, status, sizeof(status), 0);
						send(target, encryptedResponse, len, 0);
						printf("Private message sent from %i to %i: %s\n", i, target, encryptedResponse + 11);

					} else if (!strncmp(decryptedMessage, "password /kick", 14)) {
						int target = atoi((const char *) &line[16]);	
						printf("Kick command receieved from user %i for user %i\n", i, target);
						for (x = 0; x < numUsers; x++) {
							if (users[x] == target) {
								printf("Kicking user %i\n", users[x]);

								strcpy(line, "/quit\n\0");
								send(users[x], line, strlen(line), 0);

								FD_CLR(users[x], &sockets);
								close(users[x]);
								users[x] = -1;
							}
						}

					} else {
						// Broadcast message to all users
						printf("Broadcasting from client %i\n", i);
						sprintf(status+17, "Broadcast from client %i:", i);
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1 && users[x] != i) {
								unsigned char encryptedMessage[256];
								RAND_bytes(iv,16);
								printf("Generated IV: %s\n", iv);
								memcpy(status, iv, 16);

								int len = encrypt(decryptedMessage, strlen(decryptedMessage), keys[x], iv, encryptedMessage);
								status[16] = len;

								send(users[x],status,sizeof(status),0);
								send(users[x],encryptedMessage,len,0);
								printf("Sent to %i\n", users[x]);
							}
						}

						printf("\n");
					}
				}
			}
		}
	}
}
