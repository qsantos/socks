#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>

#include "socket.h"

// read some bytes from socket 'from' and write them to socket 'to'
// returns 1 if EOF
static char passThrough(int from, int to)
{
	char buffer[256];
	int n = read(from, buffer, 256);

	if (n < 0) // error
	{
		fprintf(stderr, "err: %s (%i)\n", strerror(errno), errno);
		exit(1);
	}
	else if (n == 0) // EOF
		return 1;

	write(to, buffer, n);
	return 0;
}

// send data from one another until EOF
// returns 0 if a ended the connection, 1 if b did
static char passAll(int a_in, int a_out, int b_in, int b_out)
{
	int maxfd = a_in > b_in ? a_in : b_in;
	fd_set fds;
	FD_ZERO(&fds);
	char a_EOF = 0;
	char b_EOF = 0;
	while (1)
	{
		if (!a_EOF) FD_SET(a_in, &fds);
		if (!b_EOF) FD_SET(b_in, &fds);
		int res = select(maxfd+1, &fds, NULL, NULL, NULL);
		if (res < 0)
		{
			perror("select()");
			exit(1);
		}
		else if (FD_ISSET(a_in, &fds))
		{
			a_EOF = passThrough(a_in, b_out);
			FD_CLR(a_in, &fds);
		}
		else if (FD_ISSET(b_in, &fds))
		{
			b_EOF = passThrough(b_in, a_out);
			FD_CLR(b_in, &fds);
		}
	}
}

// assume socket is connected to a SOCKS4 proxy; ask it to connect to host:port
// supports IPv4/domain address
// return 'socket' on success, opposite of server response otherwise
// 'user' and 'pass' are ignored
static int socks4(int socket, char* host, char* port, char* user, char* pass)
{
	(void) user;
	(void) pass;

	if (socket < 0)
		return TCP_Connect(host, port);

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

	return buffer[1] == 0x5a ? socket : -buffer[1];;
}

// assume socket is connected to a SOCKS5 proxy; ask it to connect to host:port
// supports IPv4/domain/IPv6 address
// if 'user' and 'pass' are non-null, performs username/password authentication
// return 'socket' on success, opposite of server response otherwise
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
static int socks5(int socket, char* host, char* port, char* user, char* pass)
{
	if (socket < 0)
		return TCP_Connect(host, port);

	// VNM
	static char auth[3] = { 0x05, 0x01 };
	auth[2] = user && pass ? 0x02 : 0x00;
	write(socket, auth, 3);
	static char res[2];
	read(socket, res, 2);
	if (res[1])
		return -res[1];

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
			return -tmp;
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

	return rep ? -rep : socket;
}

static void usage(int argc, char** argv)
{
	(void) argc;
	fprintf
	(
		stderr,
		"Usage: %s mode [OPTIONS] [-f file|proxy1 [proxy2...]]\n"
		"The proxies are chained to strenghten privacy\n"
		"\n"
		"mode:\n"
		"  cat    c  stdin and stdout are piped through the proxy chain\n"
		"  serve  s  starts a server sending data through the chain\n"
		"  check  k  check the proxy chain\n"
		"\n"
		"OPTIONS:\n"
		"  --continue  -c  ignore any unreachable proxy and test the next one\n"
		"  --verbose   -v  show more information\n"
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
	CAT,
	SERVE,
	CHECK,
} Mode;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		usage(argc, argv);
		exit(1);
	}

	int argi = 1;

	Mode mode;
	char* modestr = argv[argi];
	if (!strcmp("cat", modestr) || !strcmp("c", modestr))
		mode = CAT;
	else if (!strcmp("serve", modestr) || !strcmp("s", modestr))
		mode = SERVE;
	else if (!strcmp("check", modestr) || !strcmp("k", modestr))
		mode = CHECK;
	else
	{
		usage(argc, argv);
		exit(1);
	}
	argi++;

	char o_continue = 0;
	char o_verbose  = 0;
	while (1)
	{
		char* optstr = argv[argi];
		if (!strcmp("--continue", optstr) || !strcmp("-c", optstr))
			o_continue = 1;
		else if (!strcmp("--verbose", optstr) || !strcmp("-v", optstr))
			o_verbose = 1;
		else
			break;
		argi++;
	}

	FILE* f;
	if (argi+1 < argc && !strcmp("-f", argv[argi]))
	{
		argi++;
		f = fopen(argv[argi], "r"); // proxies in file
		argi++;
		if (!f)
		{
			fprintf(stderr, "Could not open input file\n");
			exit(1);
		}
	}
	else if (argi < argc)
		f = NULL; // proxies in arguments
	else if (mode == CAT)
	{
		// stdin would be used both for proxy list and communication
		fprintf(stderr, "What are you trying to do with my stdin?!\n");
		exit(1);
	}
	else
		f = stdin; // only for proxy checking

	char currentHasSOCKS5 = 0;
	int proxy = -1;
	char* line = NULL;
	size_t n_line = 0;
	int depth = 0;
	while (1)
	{
		// get next proxy information from file/arguments
		if (f)
		{
			getline(&line, &n_line, f);
			if (feof(f))
				break;
		}
		else if (argi >= argc)
			break;

		// parse proxy host, port, type and credentials
		char* host = strtok(f ? line : argv[argi++], " \t:");
		char* port = strtok(NULL, " \t:\n");
		if (!host || !port)
			break;
		char* type = strtok(NULL, " \t:\n");
		char* user = strtok(NULL, " \t:\n");
		char* pass = strtok(NULL, " \t:\n");
		char nextHasSOCKS5 = type && !strcmp(type, "socks5");

		if (o_verbose)
			fprintf(stderr, "> %s:%s\n", host, port);

		// proceed to connect through it
		int res = (currentHasSOCKS5 ? socks5 : socks4)(proxy, host, port, user, pass);
		if (res < 0)
		{
			fprintf(stderr, "no %i: Could not reach %s:%s (%i)\n", depth, host, port, res);
			if (!o_continue)
			{
				if (proxy >= 0)
					close(proxy);
				exit(1);
			}
		}
		else
		{
			depth++;
			if (proxy < 0)
				proxy = res;
			if (mode == CHECK)
				fprintf(stdout, "%-15s:%5s:%s\n", host, port, currentHasSOCKS5 ? "socks5" : "socks4");
		}
		currentHasSOCKS5 = nextHasSOCKS5;
	}
	if (f)
	{
		free(line);
		fclose(f);
	}

	if (mode == CAT)
	{
		if (o_verbose)
			fprintf(stderr, "> Connected\n");

		int res = passAll(0, 1, proxy, proxy);
		if (o_verbose)
		{
			if (res)
				fprintf(stderr, "Remote closed\n");
			else
				fprintf(stderr, "Local closed\n");
		}

		close(proxy);
	}
	if (mode == SERVE)
	{
		int server = TCP_Listen("4242");
		if (o_verbose)
			fprintf(stderr, "> Awaiting connection\n");

		int client = TCP_Accept(server);
		if (o_verbose)
			fprintf(stderr, "> Client connected\n");

		passAll(client, client, proxy, proxy);

		close(client);
		close(server);
		close(proxy);
	}

	return 0;
}
