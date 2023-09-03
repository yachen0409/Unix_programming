
#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()
#define SA struct sockaddr
int main(){
    int sockfd, connfd;
    struct sockaddr_in* servaddr;
 
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
    servaddr->sin_family = AF_INET;
    servaddr->sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr->sin_port = htons(6666);
    printf("%lx\n", (servaddr)->sin_family);
    return 0;

}