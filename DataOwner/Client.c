#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 3490
#define MAXSIZE 1024

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[1024];
    char buff[1024];

    if (argc != 2) {
        fprintf(stderr, "Usage: client hostname\n");
        exit(1);
    }

    if ((he = gethostbyname(argv[1]))==NULL) {
        fprintf(stderr, "Cannot get host name\n");
        exit(1);
    }

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket Failure!!\n");
        exit(1);
    }

    memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(PORT);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        perror("connect");
        exit(1);
    }
memset(buffer,0,1024);
	char file[30];
        printf("Client: Enter file name for Server:\n");
//	fgets(file,30,stdin);
        scanf("%s",file);
	FILE *fp=fopen(file,"r");
        fgets(buffer,MAXSIZE-1,fp);

	printf("content read from file %s\n",buffer);
        if ((send(socket_fd,buffer, strlen(buffer),0))== -1) {
	        fprintf(stderr, "Failure Sending Message\n");
                close(socket_fd);
                exit(1);
            }
            else {
		    char *sze;int size;
		sze=malloc(sizeof(int));
                    printf("Client:Message being sent: %s\n",buffer);
		    num=recv(socket_fd,sze,sizeof(int),0);
		    size=atoi(sze);	
		    printf("size= %d",size);
		memset(buffer,0,1024);
                    num=recv(socket_fd, buffer,(int)size,0);
                    if ( num <= 0 )
                    {
                            printf("Either Connection Closed or Error\n");
				return 0;
                    }
		    FILE * fp_bin=fopen("PrivK.bin","w");
		    fprintf(fp_bin,"%s",buffer);
                    printf("Client:Message Received From Server %d\n",(int)strlen(buffer));
               }
        close(socket_fd);  
}
