#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

int main(int argc, char **argv){
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	int users[10];
	int numUsers = 0;

	fd_set sockets; //fd stands for file descriptor
	FD_ZERO(&sockets);

	printf("Input desired port\n");
	char temp[6];
	fgets(temp, sizeof(temp), stdin);
	int port = atoi(temp);

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

	while(1){
		// keep copy of original set before destructive operation select
		fd_set tmp_set = sockets;
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);

		for (i = 0; i < FD_SETSIZE; i++ ) {
			if (FD_ISSET(i, &tmp_set)) {
				if (i == sockfd) {
					clientsocket = accept(sockfd,(struct sockaddr*)&clientaddr,(socklen_t *)&len);
					FD_SET(clientsocket, &sockets); // every time I receive a client, also add it to the set

					users[numUsers] = clientsocket; 
					numUsers++;

				} else if (i == fileno(stdin)) { // send	
					char line[5000];
					fgets(line, sizeof(line), stdin);

					// handle commands
					if (line[0] == '/') {
						if (!strncmp(line, "/list", 5)) {
							for (x = 0; x < FD_SETSIZE; x++) {
								if (FD_ISSET(x, &sockets) && x != fileno(stdin) && x != sockfd)
									printf("User: %i\n", x);
							}
							printf("\n");
						} else if (!strncmp(line, "/message", 8)) {

						} else if (!strncmp(line, "/kick", 5)) {
							//if (
						} else if (!strncmp(line, "/quit", 5)) {
							send(clientsocket,line,strlen(line)+1,0);
							printf("Shutting down server\n");

							// remove all FDs from set and exit
							for (x = 0; x < FD_SETSIZE; x++) {
								if (FD_ISSET(x, &sockets)) {
									FD_CLR(x, &sockets);
									close(x);
								}
							}
							exit(0);
						} else {
							printf("Invalid command\n");
						}
					} else {
						// Send server message to all users
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1) {
								send(users[x],line,strlen(line)+1,0);
							}
						}
					}
				}
				
				else { // can receive if not sending socket (sockfd)
					char line[5000];
					recv(i,line,5000,0);
					printf("Broadcasting from client %i: %s\n",i,line);
					if (!strcmp(line,"/quit\n")) {
						printf("Client %i Quitting\n",i);
						
						// Omit user from table
						for (x = 0; x < numUsers; x++) {
							if (users[x] == i) {
								users[x] = -1;
								break;
							}
						}
						
						// remove from FD_SET so it doesn't claim we can read data from a closed socket, then close
						FD_CLR(i,&sockets);
						close(i);
					} else if (!strncmp(line, "/list", 5)) {
						for (x = 0; x < FD_SETSIZE; x++) {
							if (FD_ISSET(x, &sockets) && x != fileno(stdin) && x != sockfd)
								sprintf(line,"User: %i\n", x);
								send(i,line,strlen(line)+1,0);
						}
						printf("\n");
					} else if (!strncmp(line, "/message", 8)) {

					} else {
						// Broadcast message to all users
						char status[24];
						strncpy(status, "Broadcast from server ", 21);
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1) {
								status[22] = x;
								status[23] = ':';
								send(users[x],status,strlen(line)+1,0);
								send(users[x],line,strlen(line)+1,0);
							}
						}
					}
				}
			}
		}
	}
}
