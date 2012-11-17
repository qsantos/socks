#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#include "types.h"
#include "socket.h"

void passThrough(u32 from, u32 to)
{
	char buffer[256];
	u32 n = read(from, buffer, 256);
	write(to, buffer, n);
}

int main(int argc, char** argv)
{
	assert(argc > 1);
	
	string host = strtok(argv[1], ":");
	string port = strtok(NULL, "");
	int proxy = TCP_Connect(host, port);
	if (proxy < 0)
	{
		fprintf(stderr, "local: Could not reach proxy no 1\n");
		return 1;
	}
	
	for (s32 i = 2; i < argc; i++)
	{
		static u8 greeting[9] = { 0x04, 0x01 };
		static u8 buffer[8];
		
		host = strtok(argv[i], ":");
		port = strtok(NULL, "");
		bool isIP = inet_pton(AF_INET, host, greeting + 4);
		if (!isIP)
		{
			greeting[4] = 0;
			greeting[5] = 0;
			greeting[6] = 0;
			greeting[7] = 1;
			printf("%s\n", host);
		}
		*(u16*)(greeting+2) = htons(atoi(port));
		
		write(proxy, greeting, 9);
		if (!isIP)
			write(proxy, host, strlen(host)+1);
		read(proxy, buffer, 8);
		u8 status = buffer[1];
		
		if (status == 0x5A)
			continue;
		
		if (status == 0x5B)
		{
			if (i == argc - 1)
				fprintf(stderr, "no %lu: Could not reach final target (%s)\n", i-1, host);
			else
				fprintf(stderr, "no %lu: Could not reach proxy no %lu (%s)\n", i-1, i, host);
		}
		else if (status == 0x5C)
			fprintf(stderr, "no %lu: Not running identd (client not reachable)\n", i-1);
		else if (status == 0x5D)
			fprintf(stderr, "no %lu: Authentication failed\n", i-1);
		else
			fprintf(stderr, "no %lu: Unknown status from server (%2.X)\n", i-1, status);
		close(proxy);
		return 1;
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
