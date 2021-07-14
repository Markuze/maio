#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#define CHUNK (16<<12)
#define CHUNK_NUM 2000
#define MAX CHUNK*CHUNK_NUM
#define PORT 8080
#define SA struct sockaddr

char buff[MAX];

const int K_MSGZEROCOPY=0;
const int K_FILES = 2000;
const char* K_FILE_PATH = "/home/igolikov/files/";

void func(int sockfd)
{
        int n;
	printf("using send with MSG_ZEROCOPY set to %d\n", K_MSGZEROCOPY);

	int offset = 0;
        while (1) {
                send(sockfd, buff + offset, CHUNK, K_MSGZEROCOPY ? MSG_ZEROCOPY : 0);
		if(++offset == CHUNK_NUM)
			offset = 0;

        }
}

// assumes that there are K_FILES-1 files with size MAX at K_FILE_PATH, with read permissions
void func1(int sockfd) {
	printf("using sendfile\n");

	int files_desc[K_FILES];
	char path[100];
	strcpy(path, K_FILE_PATH);
	// printf("path1: %s\n", path);

	char fileName[10];
	for(int i = 0; i < K_FILES; ++i) {
		sprintf(fileName, "%d", i);
		// printf("file name: %s\n", fileName);
		strcpy(path + strlen(K_FILE_PATH), fileName);
		// printf("path: %s\n", path);
		files_desc[i] = open(path, O_RDONLY);
	}

	int next_file_idx = 0;
	while(1) {
		off_t offset = 0;
		size_t res = sendfile(sockfd, files_desc[next_file_idx], NULL, MAX);
		// printf("res: %ld\n", res);
		lseek(files_desc[next_file_idx], 0, SEEK_SET); 
		if(++next_file_idx == K_FILES)
			next_file_idx = 0;
	}

	for(int i = 0; i < K_FILES; ++i)
		close(files_desc[i]);		
}


int main(int argc, char** argv)
{
	uint port;
        if(argc == 1) port = PORT;
        else port = strtol(argv[1], NULL, 10);
        printf("connecting to port %d\n", port);

        int sockfd, connfd;
        struct sockaddr_in servaddr, cli;

        // socket create and varification
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
                printf("socket creation failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

	if(K_MSGZEROCOPY) {
		if (setsockopt(sockfd, SOL_SOCKET, SO_ZEROCOPY, &K_MSGZEROCOPY, sizeof(K_MSGZEROCOPY)))
		       printf("setsockopt zerocopy error\n");
		printf("socket zerocopy set\n");
	}

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr("10.128.0.3");
        //servaddr.sin_addr.s_addr = inet_addr("10.5.3.4");
        servaddr.sin_port = htons(port);

        // connect the client socket to server socket
        if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                printf("connection with the server failed...\n");
                exit(0);
        }
        else
                printf("connected to the server..\n");

	

        // function for chat
	func(sockfd);
	// func1(sockfd);

        // close the socket
        close(sockfd);
}
