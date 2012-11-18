#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#include "socket.h"

// read some bytes from socket 'from' and write them to socket 'to'
void passThrough(int from, int to)
{
	char buffer[256];
	int n = read(from, buffer, 256);
	write(to, buffer, n);
}

// assume socket is connected to a SOCKS4 proxy; ask it to connect to host:port
// supports IPv4/domain address
// return 0 on success, server response otherwise
// 'user' and 'pass' are ignored
int socks4(int socket, char* host, char* port, char* user, char* pass)
{
	(void) user;
	(void) pass;

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

	return buffer[1] == 0x5a ? 0 : buffer[1];;
}

// assume socket is connected to a SOCKS5 proxy; ask it to connect to host:port
// supports IPv4/domain/IPv6 address
// if 'user' and 'pass' are non-null, performs username/password authentication
// return 0 on success, server response otherwise
//
// The comments give the form of the message sent to the proxy with:
// V version
// N length
// M method
// C command
// R reserved
// F family
// A address
// P port
int socks5(int socket, char* host, char* port, char* user, char* pass)
{
	// VNM
	static char auth[3] = { 0x05, 0x01 };
	auth[2] = user && pass ? 0x02 : 0x00;
	write(socket, auth, 3);
	static char res[2];
	read(socket, res, 2);
	if (res[1])
		return res[1];

	if (user && pass)
	{
		char tmp;
		tmp = 0x05;         write(socket, &tmp,  1);   // VER
		tmp = strlen(user); write(socket, &tmp,  1);   // ULEN
		                    write(socket, &user, tmp); // UNAME
		tmp = strlen(pass); write(socket, &tmp,  1);   // PLEN
		                    write(socket, &pass, tmp); // PASSWD

		read(socket, &tmp, 1); // version
		read(socket, &tmp, 1); // status
		if (tmp)
			return tmp;
	}

	char IPgreeting[22] = { 0x05, 0x01, 0x00 };
	char* greeting = IPgreeting;
	char tofree = 0;
	int offset;
	if (inet_pton(AF_INET, host, greeting + 4))
	{
		greeting[3] = 0x01; // VCRFAAAAPP
		offset = 8;
	}
	else if (inet_pton(AF_INET6, host, greeting + 4))
	{
		greeting[3] = 0x04; // VCRFAAAAAAAAAAAAAAAAPP
		offset = 20;
	}
	else
	{
		char len = strlen(host);
		greeting = (char*) malloc(7 + len);
		greeting[0] = 0x05;
		greeting[1] = 0x01;
		greeting[3] = 0x03; // VCFRNA..APP
		greeting[4] = len;
		memcpy(greeting+4, &len, 1);
		memcpy(greeting+5, host, len);
		offset = len + 5;
		tofree = 1;
	}
	short ns_port = htons(atoi(port));
	memcpy(greeting+offset, &ns_port, 2);

	write(socket, greeting, offset+2);
	read (socket, greeting, offset+2);

	char rep = greeting[1];
	if (tofree) 
		free(greeting);

	return rep;
}

void usage(int argc, char** argv)
{
	(void) argc;
	fprintf
	(
		stderr,
		"Usage: %s mode [-f file|proxy1 [proxy2...]]\n"
		"\n"
		"mode:\n"
		"  path   p  make a proxy chain to the target\n"
		"  check  c  check that each proxy works\n"
		"\n"
		"proxies: the list of proxies can be given as the arguments of the command line\n"
		"         or as a file (one per line) ; if no option is given, stdin is assumed\n"
		"         a proxy is of the form\n"
		"\n"
		"host:port[:type[:user:pass]]\n"
		"  host   is an IPv4, IPv6 (not after a SOCKS4 proxy) or domain address\n"
		"  port   is the port where the server listens for connections\n"
		"  type   optionnal, can be either 'socks4' or 'socks5'\n"
		"  user   optionnal, used for username/password authentication\n"
		"  pass   optionnal, used for username/password authentication\n"
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
	// used for proxy checking as the destination target
	// TODO : configure with parameters
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
		f = fopen(argv[3], "r"); // proxies in file
		if (!f)
		{
			fprintf(stderr, "Could not open input file\n");
			return 1;
		}
	}
	else if (argc >= 3)
		f = NULL; // proxies in arguments
	else if (mode == PATH)
	{
		// stdin would be used both for proxy list and communication
		fprintf(stderr, "What are you trying to do with my stdin?!\n");
		return 1;
	}
	else
		f = stdin; // only for proxy checking

	char currentHasSOCKS5 = 0;
	int proxy = -1;
	char* line = NULL;
	size_t n_line = 0;
	int no = 0;
	while (1)
	{
		// get next proxy information from file/arguments
		if (f)
		{
			getline(&line, &n_line, f);
			if (feof(f))
				break;
		}
		else if (no+2 > argc)
			break;

		// parse proxy host, port, type and credentials
		char* host = strtok(f ? line : argv[no+2], ":");
		char* port = strtok(NULL, ":\n");
		if (!host || !port)
			break;
		char* type = strtok(NULL, ":\n");
		char* user = strtok(NULL, ":\n");
		char* pass = strtok(NULL, ":\n");
		char nextHasSOCKS5 = type && !strcmp(type, "socks5");

		// proceed to connect through it
		int res;
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
			else
			{
				res = (currentHasSOCKS5 ? socks5 : socks4)(proxy, host, port, user, pass);
				if (res)
				{
					fprintf(stderr, "no %i: Could not reach %s (%i)\n", no, host, res);
					close(proxy);
					return 1;
				}
			}
			currentHasSOCKS5 = nextHasSOCKS5;
			break;
		case CHECK:
			proxy = TCP_Connect(host, port);
			currentHasSOCKS5 = nextHasSOCKS5;
			if (proxy >= 0)
			{
				if ((currentHasSOCKS5 ? socks5 : socks4)(proxy, targetHost, targetPort, user, pass) == 0)
					fprintf(stdout, "%s:%s:%s\n", host, port, currentHasSOCKS5 ? "socks5" : "socks4");
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
		fprintf(stderr, "> Connected\n");

		// now waits for incoming messages from stdin or socket
		// and pass them to the other end
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
