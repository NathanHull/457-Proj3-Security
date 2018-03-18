#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv){
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd<0){
		printf("There was an error creating the socket\n");
		return 1;
	}
	printf("Input desired IP\n");
	char ip[12];
	scanf("%s", ip);
	getchar();

	printf("Input desired port\n");
	int port;
	scanf("%i", &port);
	getchar();

	fd_set sockets;
	FD_ZERO(&sockets);
	FD_SET(sockfd, &sockets);
	FD_SET(fileno(stdin), &sockets);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=inet_addr(ip);

	int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	if(e<0){
		printf("There was an error connecting\n");
		return 1;
	}

	while (1) {
		fd_set tmp_set = sockets;
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
		int i;

		for (i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &tmp_set)) {
				if (i == sockfd) { // receiving msg from server
					char line[5000];
					recv(i, line, 5000, 0);
					if (strcmp(line, "Quit\n") == 0) {
						printf ("Quitting\n");
						close(i);
						FD_CLR(i, &sockets);
						return 0;
					}
					printf("Message from server: %s\n", line);
				}
				else if (i == fileno(stdin)) {
					char line[5000];
					fgets(line, 5000, stdin);
					send(sockfd, line, strlen(line) + 1, 0);
					if (strcmp(line, "Quit\n") == 0) {
						close(sockfd);
						FD_CLR(sockfd, &sockets);
						printf("Quitting\n");
						return 0;
					}
				}
			}

		}
	}
	close(sockfd);
	return 0;

}
