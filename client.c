#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

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

	while (1) {
		fd_set tmp_set = sockets;
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
		int i;

		for (i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &tmp_set)) {
				if (i == sockfd) { // receiving msg from server
					char status[25];
					char line[1000];

					recv(i, status, 25, 0);
					printf("%s ", status);

					if (strncmp(status, "/quit", 5) == 0) {
						printf ("Quitting\n");
						close(i);
						FD_CLR(i, &sockets);
						return 0;
					}

					recv(i, line, 1000, 0);
					printf("%s\n", line);
				}

				else if (i == fileno(stdin)) {
					char line[1000];
					fgets(line, 1000, stdin);
					send(sockfd, line, strlen(line) + 1, 0);

					if (strcmp(line, "/quit\n") == 0) {
						close(sockfd);
						FD_CLR(sockfd, &sockets);
						printf("Quitting\n");
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
