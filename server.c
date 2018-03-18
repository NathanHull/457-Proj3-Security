#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

int main(int argc, char **argv){
	int sockfd = socket(AF_INET,SOCK_STREAM,0);

	fd_set sockets; //fd stands for file descriptor
	FD_ZERO(&sockets);

	printf("Input desired port\n");
	char temp[6];
	fgets(temp, sizeof(temp), stdin);
	int port = atoi(temp);

	struct sockaddr_in serveraddr,clientaddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=INADDR_ANY;

	bind(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	listen(sockfd,10);

	FD_SET(sockfd, &sockets);  //put sockfd into sockets set
	FD_SET(fileno(stdin), &sockets);
	int clientsocket;

	while(1){
		int len=sizeof(clientaddr);
		fd_set tmp_set = sockets; // keep copy of original set before destructive operation select
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL); // last param is timeout length
		int i;
		for (i = 0; i < FD_SETSIZE; i++ ) {
			if (FD_ISSET(i, &tmp_set)) {
				if (i == sockfd) {
					clientsocket = accept(sockfd,(struct sockaddr*)&clientaddr,&len);
					FD_SET(clientsocket, &sockets); // every time I receive a client, also add it to the set
					
				} else if (i == fileno(stdin)) { // send	
					char line[5000];
					fgets(line, sizeof(line), stdin);
					send(clientsocket,line,strlen(line)+1,0);
					if (strcmp(line, "Quit") == 0) {
						printf("Quitting\n");
						close(i);
						FD_CLR(i,&sockets); // remove from FD_SET so it doesn't claim we can read data from a closed socket
						FD_CLR(sockfd,&sockets);
						exit(0);
					}
				}
				
				else { // can receive if not sending soccket (sockfd)
					char line[5000];
					recv(i,line,5000,0);
					printf("Got from client: %s\n",line);
					if (strcmp(line, "Quit\n") == 0) {
						printf("Quitting\n");
						close(i);
						FD_CLR(i,&sockets); // remove from FD_SET so it doesn't claim we can read data from a closed socket
						FD_CLR(sockfd,&sockets);
						exit(0);
					}
				}
			}
		}
	}
}
