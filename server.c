#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

int main(int argc, char **argv){
	int sockfd = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
	int users[10];
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
					numUsers++;




				// =====================================================
				// Handle server input
				// =====================================================
				} else if (i == fileno(stdin)) {
					char status[25];
					char line[1000];
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

							for (x = 0; x < FD_SETSIZE; x++) {
								if (FD_ISSET(x, &sockets)) {
									printf("Closing %i\n",x);
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
					char status[25];
					char line[1000];
					char response[1000];

					recv(i,line,1000,0);
					printf("From client %i: %s\n",i,line);

					if (!strcmp(line,"/quit\n")) {
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

					} else if (!strcmp(line, "/list\n")) {
						strcpy(status, "Clients:");
						int curr = 0;
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1) {
								response[curr] = '0' + users[x];
								curr++;
								response[curr] = ' ';
								curr++;
							}
						}
						response[curr] = '\n';

						send(i,status,sizeof(status),0);
						send(i,response,strlen(line)+1,0);
						printf("List sent to user %i\n", i);
						printf("\n");

					} else if (!strncmp(line, "/message", 8)) {
						int target = atoi((const char *) &line[9]);
						printf("Private message sent from %i to %i: %s\n", i, target, line + 10);
						sprintf(status, "Private msg from user %i:", i);
						send(target, status, sizeof(status), 0);
						send(target, line+10, strlen(line)-9, 0);

					} else if (!strncmp(line, "password /kick", 14)) {
						int target = atoi((const char *) &line[15]);	
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
						sprintf(status, "Broadcast from client %i:", i);
						for (x = 0; x < numUsers; x++) {
							if (users[x] != -1 && users[x] != i) {
								send(users[x],status,strlen(status)+1,0);
								send(users[x],line,strlen(line)+1,0);
							}
						}

						printf("\n");
					}
				}
			}
		}
	}
}
