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
#include "common.h"
#define PORT 3490
#define BACKLOG 10
struct Index ind;
pairing_t pairing;
struct PrivateKey PrivK;
struct Trapdoor trapdoor;

#include <mysql/my_global.h>
#include <mysql/mysql.h>
#include <string.h>



void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);
}

void store_in_database(struct Index ind){
  MYSQL *con = mysql_init(NULL);
  MYSQL *con1 = mysql_init(NULL);
  //String query[1000];
  //memset(query,'\0', sizeof(query));
  int i;
  if (con == NULL)
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }

  if(mysql_real_connect(con1, "localhost", "root", "123456", NULL, 0, NULL, 0))
  {
     printf("\nNot connected\n");
     fprintf(stderr, "%s\n", mysql_error(con));
     //mysql_close(con);
     //exit(1);
  }
  printf("\nconnected\n");
  if(mysql_query(con1, "CREATE DATABASE filekeydb")){
      finish_with_error(con1);
  }
  
  if (mysql_real_connect(con, "localhost", "root","123456","filekeydb", 0, NULL, 0) == NULL)
  {
      finish_with_error(con);
  }

  printf("1\n");
  if (mysql_query(con, "DROP TABLE IF EXISTS table1")) {
      finish_with_error(con);
  }
  printf("2\n");

  if (mysql_query(con, "CREATE TABLE table1(Id1 INT,Id2 INT, Id3 INT)")) {     
      finish_with_error(con);
  }

     printf("->keyword = %d",ind.Keywords_Num);
     printf("\n-->Policy = %d\n",ind.Policy[0]);
     printf("\n-->Cipher = %d\n",ind.abeaesciphertext.abeaesciphertext[0].Policy[0]);
*/
 //the first part of index
  unsigned char *Dhatstorage = malloc(65);//store this
  unsigned char *Dprimestorage = malloc(128);//store this
  unsigned char** Dstorage = malloc(sizeof(unsigned char*)*ATT_NUM);//store this
  for(i = 0; i < ATT_NUM; i++)
    Dstorage[i] = malloc(65);

 // element_printf("ind.D_hat before transmission is %B\n", ind.D_hat);
  /*element_to_bytes_compressed(Dhatstorage, ind.D_hat);
  element_printf("ind.D_prime before transmission is %B\n", ind.D_prime);
  element_to_bytes(Dprimestorage, ind.D_prime);
  for(i = 0; i < ATT_NUM; i++)
    element_printf("ind.D is %B\n", ind.D[i]);  
  for(i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(Dstorage[i], ind.D[i]);
  
  //the second part of index
  unsigned char *C0hatstorage = malloc(128);//store this
  unsigned char *C0primestorage = malloc(65);//store this
  unsigned char** C0storage = malloc(sizeof(unsigned char*)*ATT_NUM);//store this
  for(i = 0; i < ATT_NUM; i++)
    C0storage[i] = malloc(65);
 
  element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_hat is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_hat);
  element_to_bytes(C0hatstorage, ind.abeaesciphertext.abeaesciphertext[0].C_hat);
  element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_prime is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_prime);
  element_to_bytes_compressed(C0primestorage, ind.abeaesciphertext.abeaesciphertext[0].C_prime);
  for(i = 0; i < ATT_NUM; i++)
    element_printf("ind.abeaesciphertext.abeaesciphertext[0].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C[i]);  
  for(i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(C0storage[i], ind.abeaesciphertext.abeaesciphertext[0].C[i]);                                
          
  unsigned char *C1hatstorage = malloc(128);//store this
  unsigned char *C1primestorage = malloc(65);//store this
  unsigned char** C1storage = malloc(sizeof(unsigned char*)*ATT_NUM);//store this
  for(int i = 0; i < ATT_NUM; i++)
      C1storage[i] = malloc(65);
          
  element_printf(" ind.abeaesciphertext.abeaesciphertext[1].C_hat is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_hat);
  element_to_bytes(C1hatstorage, ind.abeaesciphertext.abeaesciphertext[1].C_hat);
  element_printf(" ind.abeaesciphertext.abeaesciphertext[1].C_prime is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_prime);
  element_to_bytes_compressed(C1primestorage, ind.abeaesciphertext.abeaesciphertext[1].C_prime);
  for(int i = 0; i < ATT_NUM; i++)
      element_printf("ind.abeaesciphertext.abeaesciphertext[1].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C[i]);  
  for(int i = 0; i < ATT_NUM; i++)
      element_to_bytes_compressed(C1storage[i], ind.abeaesciphertext.abeaesciphertext[1].C[i]);    
*/
}

void main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int status,socket_fd, client_fd,num;
    socklen_t size;
    char *file_name;
//    memset(file_name,0,40);
    char buffer[10241];
    char *buff;
    int yes =1;
    
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket failure!!\n");
        exit(1);
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    memset(&server, 0, sizeof(server));
    memset(&dest,0,sizeof(dest));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY; 
    if ((bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr )))== -1)    { //sizeof(struct sockaddr) 
        fprintf(stderr, "Binding Failure\n");
        exit(1);
    }

    if ((listen(socket_fd, BACKLOG))== -1){
        fprintf(stderr, "Listening Failure\n");
        exit(1);
    }

    while(1) {
            size = sizeof(struct sockaddr_in);
            if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size)) ==-1 ) {
                perror("accept");
                exit(1);
            }
            printf("Server got connection from client %s\n", inet_ntoa(dest.sin_addr));
	
            while(1) 
	    {
                memset(&buffer, 0, sizeof(buffer));
		//Read index of file
	        if ((num = recv(client_fd, (char*)&ind, sizeof(ind),0))== -1) {
                    perror("recv");
                    exit(1);
                }
                else if (num == 0) {
                    printf("Connection closed\n");
                    //So I can now wait for another client
                    break;
                }
		printf("File index Received\n");

                store_in_database(ind);
		printf("\nkeyword = %d",ind.Keywords_Num);
		printf("\nPolicy = %d\n",ind.Policy[0]);
	

		char* sze;int size;

                if ((num = recv(client_fd, buffer, sizeof(buffer),0))== -1) {
                     perror("recv");
                     exit(1);
                }
                else if (num == 0) {
                     printf("Connection closed\n");
                     //So I can now wait for another client
                     break;
                }
	
                buffer[num] = '\0';
                //printf("Server:Msg Received %s\n", buffer);
		char buf_write[9]="Received";                    
                if ((send(client_fd,buf_write, 9,0))== -1) 
                {
                     fprintf(stderr, "Failure Sending Message\n");
                     close(client_fd);
                     break;
                }
		file_name=strtok(buffer,"$");
	//	printf("server:File Name: %s\n",file_name);
		char* file_buf=strtok(NULL,"$");

	//	printf("server:Contents of File: %s of size: %zu\n",file_buf, strlen(file_buf));
		FILE *fp_buf=fopen(file_name,"w");
		if(NULL==fp_buf){
			printf("error opening file\n");
			close(client_fd);
                        break;
		}
	//	fprintf(fp_buf,"%s",file_buf);
		printf("Server:file stored on the server\n");
		fclose(fp_buf);

            } //End of Inner While...
            //Close Connection Socket
            close(client_fd);
        } //Outer While

        close(socket_fd);
        
}

