#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#include "socket.h"

void passThrough(int from, int to)
{
	char buffer[256];
	int n = read(from, buffer, 256);
	write(to, buffer, n);
}

int proxyto(int socket, char* host, char* port)
{
	static char greeting[9] = { 0x04, 0x01 };
	static char buffer[8];
	
	char isIP = inet_pton(AF_INET, host, greeting + 4);
	if (!isIP)
	{
		greeting[4] = 0;
		greeting[5] = 0;
		greeting[6] = 0;
		greeting[7] = 1;
		printf("%s\n", host);
	}
	short ns_port = htons(atoi(port));
	memcpy(greeting+2, &ns_port, 2);
	
	write(socket, greeting, 9);
	if (!isIP)
		write(socket, host, strlen(host)+1);
	read(socket, buffer, 8);
	char status = buffer[1];
	
	if (status == 0x5A)
		return 0;
	else
		return -1;
}

int main(int argc, char** argv)
{
	assert(argc > 1);
	
	char* host = strtok(argv[1], ":");
	char* port = strtok(NULL, "");
	int proxy = TCP_Connect(host, port);
	if (proxy < 0)
	{
		fprintf(stderr, "local: Could not reach proxy no 1\n");
		return 1;
	}
	
	for (int i = 2; i < argc; i++)
	{
		host = strtok(argv[i], ":");
		port = strtok(NULL, "");
		if (proxyto(proxy, host, port) < 0)
		{
			fprintf(stderr, "no %i: Could not reach final node (%s)\n", i-1, host);
			close(proxy);
			return -1;
		}
	}
	
	fd_set fds;
	FD_ZERO(&fds);
	while (1)
	{
		FD_SET(0, &fds);
		FD_SET(proxy, &fds);
		int res = select(proxy+1, &fds, NULL, NULL, NULL);
		if (res < 0)
		{
			perror("select()");
			return 1;
		}
		else if (FD_ISSET(0, &fds))
			passThrough(0, proxy);
		else if (FD_ISSET(proxy, &fds))
			passThrough(proxy, 0);
	}
	
	close(proxy);
	return 0;
}
