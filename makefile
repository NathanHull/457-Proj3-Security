make: server.c client.c
	gcc server.c -lcrypto -o aServer
	gcc client.c -lcrypto -o bClient
