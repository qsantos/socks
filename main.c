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
	}
	short ns_port = htons(atoi(port));
	memcpy(greeting+2, &ns_port, 2);

	write(socket, greeting, 9);
	if (!isIP)
		write(socket, host, strlen(host)+1);
	read(socket, buffer, 8);

	return buffer[1] == 0x5a ? 0 : -1;
}

void usage(int argc, char** argv)
{
	(void) argc;
	fprintf
	(
		stderr,
		"Usage: %s mode [-f file|host1:port1 [host2:port2...]]\n"
		"\n"
		"mode:\n"
		"  path   p  make a proxy chain to the tarfet\n"
		"  check  c  check that each proxy works\n"
		,
		argv[0]
	);
}

typedef enum
{
	PATH,
	CHECK,
} Mode;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		usage(argc, argv);
		return 1;
	}

	Mode mode;
	char* targetHost = "173.236.190.252";
	char* targetPort = "80";

	if (!strcmp("path", argv[1]) || !strcmp("p", argv[1]))
		mode = PATH;
	else if (!strcmp("check", argv[1]) || !strcmp("c", argv[1]))
		mode = CHECK;
	else
	{
		usage(argc, argv);
		return 1;
	}

	FILE* f;
	if (argc >= 4 && !strcmp("-f", argv[2]))
	{
		f = fopen(argv[3], "r");
		if (!f)
		{
			fprintf(stderr, "Could not open input file\n");
			return 1;
		}
	}
	else if (argc >= 3)
		f = NULL; // list given as parameters
	else if (mode == PATH)
	{
		fprintf(stderr, "What are you trying to do with my stdin?!\n");
		return 1;
	}
	else
		f = stdin; // only for proxy checking

	int proxy = -1;
	char* line = NULL;
	size_t n_line = 0;
	int no = 0;
	while (1)
	{
		if (f)
		{
			getline(&line, &n_line, f);
			if (feof(f))
				break;
		}
		else if (no+2 > argc)
			break;
		char* host = strtok(f ? line : argv[no+2], ":");
		char* port = strtok(NULL, "\n");
		if (!host || !port)
			break;
		switch (mode)
		{
		case PATH:
			fprintf(stderr, "> %s:%s\n", host, port);
			if (proxy < 0)
			{
				proxy = TCP_Connect(host, port);
				if (proxy < 0)
				{
					fprintf(stderr, "local: Could not reach proxy no 1\n");
					return 1;
				}
			}
			else if (proxyto(proxy, host, port) < 0)
			{
				fprintf(stderr, "no %i: Could not reach next node (%s)\n", no, host);
				close(proxy);
				return 1;
			}
			break;
		case CHECK:
			proxy = TCP_Connect(host, port);
			if (proxy >= 0)
			{
				if (proxyto(proxy, targetHost, targetPort) == 0)
					fprintf(stdout, "%s:%s\n", host, port);
				close(proxy);
			}
			break;
		}
		no++;
	}
	if (f)
	{
		free(line);
		fclose(f);
	}

	if (mode == PATH)
	{
		fprintf(stderr, "Connected\n");

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
				passThrough(proxy, 1);
		}

		close(proxy);
	}

	return 0;
}
