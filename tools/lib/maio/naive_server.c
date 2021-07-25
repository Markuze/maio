#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX (64 << 12)
#define PORT 8080
#define SA struct sockaddr

char buff[MAX];

// Function designed for chat between client and server.
void func(int sockfd)
{
        int n;
        // infinite loop for chat
        for (;;) {
                recv(sockfd, buff, sizeof(buff), 0);
        }
}

// Driver function
int main(int argc, char** argv)
{
	uint port;
	if(argc == 1) port = PORT;
	else port = strtol(argv[1], NULL, 10);
	printf("listening on port %d\n", port);


        int sockfd, connfd;
        unsigned int len;
        struct sockaddr_in servaddr, cli;

        // socket create and verification
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
                printf("socket creation failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(port);

        // Binding newly created socket to given IP and verification
        if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
                printf("socket bind failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully binded..\n");

        // Now server is ready to listen and verification
        if ((listen(sockfd, 5)) != 0) {
                printf("Listen failed...\n");
                exit(0);
        }
        else
                printf("Server listening..\n");
        len = sizeof(cli);

        // Accept the data packet from client and verification
        connfd = accept(sockfd, (SA*)&cli, &len);
        if (connfd < 0) {
                printf("server acccept failed...\n");
                exit(0);
        }
        else
                printf("server acccept the client...\n");

        // Function for chatting between client and server
        func(connfd);

        // After chatting close the socket
        close(sockfd);
}

