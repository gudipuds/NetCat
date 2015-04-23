#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>

#define BUF_LEN 1024

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args{
  struct sockaddr_in destaddr; //destination/server address
  unsigned short port; //destination/listen port
  unsigned short listen; //listen flag
  int n_bytes; //number of bytes to send
  int offset; //file offset
  int verbose; //verbose output info
  int message_mode; // retrieve input to send via command line
  char * message; // if message_mode is activated, this will store the message
  char * filename; //input/output file
}nc_args_t;

/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file){
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip [file] \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	     "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	     "                \t\t Warning: if you specify this option, you do not specify a file. \n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[]){
  int ch;
  struct hostent * hostinfo;
  //set defaults
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6767;
  nc_args->verbose = 0;
  nc_args->message_mode = 0;
 
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'l': //listen
      nc_args->listen = 1;
      break;
    case 'p': //port
      nc_args->port = atoi(optarg);
      break;
    case 'o'://offset
      nc_args->offset = atoi(optarg);
      break;
    case 'n'://bytes
      nc_args->n_bytes = atoi(optarg);
      break;
    case 'v':
      nc_args->verbose = 1;
      break;
    case 'm':
      nc_args->message_mode = 1;
      nc_args->message = malloc(strlen(optarg)+1);
      strncpy(nc_args->message, optarg, strlen(optarg)+1);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }
 
  argc -= optind;
  argv += optind;
 
  if (argc < 2 && nc_args->message_mode == 0){
    fprintf(stderr, "ERROR: Require ip and file\n");
    usage(stderr);
    exit(1);
  } else if (argc != 1 && nc_args->message_mode == 1) {
    fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
    usage(stderr);
    exit(1);
  }
 
  if(!(hostinfo = gethostbyname(argv[0]))){
    fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    usage(stderr);
    exit(1);
  }

  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
        hostinfo->h_length);
   
  nc_args->destaddr.sin_port = htons(nc_args->port);
   
  /* Save file name if not in message mode */
  if (nc_args->message_mode == 0) {
    nc_args->filename = malloc(strlen(argv[1])+1);
    strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
  }
  return;
}

//Calculates the Digest for the input data
unsigned char * getMsgDigest(char * data){
  unsigned char * msgDigest;
  unsigned int len = 20;
  msgDigest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);
  return msgDigest;
}

void runClient(nc_args_t * nc_args)
{
  int sockfd, fileSize, readSize, dataLen, iterator = 0, i;
  char * data, *sendData, *buffer;
  unsigned char * digest;
  FILE *fp;

  //Open Socket 
  if(nc_args->verbose)
	  printf("\n Opening the Socket...");
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1 ){
    fprintf(stderr,"Error opening socket");
	exit(1);
  }
   
  // Set Socket Address and Connect to server
  if(nc_args->verbose)
    printf("\n Initiating connection to Server...");
  if(connect(sockfd, (struct sockaddr *) &nc_args->destaddr, sizeof(struct sockaddr_in) )< 0 ){
    fprintf(stderr,"Connect Error");
    exit(1);
  }

  //Check for message mode
  if(nc_args->message_mode != 1){
    if(nc_args->verbose)
      printf("\n Reading data from file...");
    
	//Open the given file
	fp = fopen(nc_args->filename,"r");

	if(fp == NULL){
	  fprintf(stderr,"Error opening file");
      exit(1);
	}

    //Find the size of file
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, nc_args->offset, SEEK_SET);

	if( nc_args->n_bytes != 0)
	  fileSize = nc_args->n_bytes;              
    else if (nc_args->offset != 0 && nc_args->n_bytes == 0)
      fileSize -= nc_args->offset;

	//Read from file
    data =(char *)malloc(fileSize + 1);
	readSize = fread(data,1,fileSize,fp);
    data[readSize] = '\0';
	
	//Close the file
	fclose(fp);
  }
  else{
    if(nc_args->verbose)
      printf("\n Reading data...");
    data = nc_args->message;
  }

  buffer = (char *)malloc(512);
  sendData = (char *)malloc(BUF_LEN);
  dataLen = strlen(data);
  
  while( dataLen > 0 ){
    memcpy(buffer, data + iterator * 512, 512);
	if (dataLen < 512)
	  buffer[dataLen] = '\0';
	else
	  buffer[512] = '\0';
	  
	//Calculate the digest for 512 bytes of data
    if(nc_args->verbose)
      printf("\n Calculating digest and appending digest length, digest to Data");
	digest = getMsgDigest(buffer);
	
	//Append HMAC and HMAC length to the message in HMAC Length + HMAC Digest + Data order.
	sprintf(sendData, "%d+%s+%s", strlen(digest), digest, buffer);
	
	//Delaying to write onto socket from second iteration in order to prevent server from getting overloaded with multiple socket writes.
	for( i = 0; i < 15000000 && iterator != 0; i++ ){
	}
	
	//Write data to socket
    if(nc_args->verbose)
      printf("\n Writing data to Socket...");
	write(sockfd,sendData,strlen(sendData));
	
	iterator += 1;
	dataLen -= 512;
  }

  free(sendData);
  free(data);
  
  //Close the Socket
  if(nc_args->verbose)
    printf("\n Closing the Socket...");
  close(sockfd);
}

void runServer(nc_args_t * nc_args)
{
  int serverSock, clientSock, clientAddrLen, readSize, len, digestLen;
  struct sockaddr_in clientAddr;
  char data[512], recvData[BUF_LEN];
  unsigned char * digest;
  char runServ = 'y';
  
  digest = (unsigned char * )malloc(20);
  
  //Open server socket for listening
  if(nc_args->verbose)
    printf("\n Opening the Socket...");
  serverSock = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSock == -1 ){
    fprintf(stderr,"Error opening socket");
	exit(1);
  }

  //Bind socket to a port
  if(nc_args->verbose)
    printf("\n Binding the Socket to the given port...");
  if (bind(serverSock, (struct sockaddr *) &nc_args->destaddr, sizeof(struct sockaddr_in)) < 0 ){
    fprintf(stderr,"Bind Error");
	exit(1);
  }
   
  //Listen to conections
  if(nc_args->verbose)
    printf("\n Listening to connections...");
  listen(serverSock, 5);
   
  //Accept a connection and read data 
  //while(runServ == 'y'){
    clientAddrLen = sizeof(clientAddr);

    //Accept a connection from the client
	if(nc_args->verbose)
    printf("\n Accepting a client connection...");
    clientSock = accept(serverSock, (struct sockaddr *) &clientAddr, &clientAddrLen);
	if( clientSock < 0){
	  fprintf(stderr,"Accept Error");
	  exit(1);
	}
	
    //Open the output file in write mode to clear the file(if the file has any contents)
	FILE *fp;
	if(nc_args->verbose)
    printf("\n Opening the output file...");
    fp = fopen(nc_args->filename,"w");
	if(fp == NULL) {
	  fprintf(stderr,"Error creating file");
	  exit(1);
	}
	
	//Close the file and open it in append mode
	fclose(fp);
	fp = fopen(nc_args->filename,"a");
	if(fp == NULL) {
	  fprintf(stderr,"Error creating file");
	  exit(1);
	}
	
	//Read data from socket
	while((readSize = read( clientSock, recvData, BUF_LEN)) > 0 ) {
	   recvData[readSize] = '\0';
	   
	   //Extracting the message digest length
	   if( recvData[1] =='+' ){
	     digestLen = recvData[0] - '0';
         len = 2;		 
	   }
	   else {
	     digestLen = (recvData[0] - '0')*10 + (recvData[1]-'0');
		 len = 3;
	   }
	   
	   //Extracting the digest for the given message
	   memcpy(digest, recvData + len, digestLen);
	   digest[digestLen] = '\0'; 
	   
	   //Extracting the actual data from the message
	   data[0]='\0';
	   strcpy(data, recvData + len + digestLen + 1);
	   
	   //Comparing the digest from the client and the calculated digest of the data received
	   if (strcmp(digest,getMsgDigest(data)) == 0){
	   //Writing the data to the file
	   if(nc_args->verbose)
         printf("\n Writing to the output file...");
	   fwrite(data, 1, readSize - digestLen - 1 - len, fp);
	   }
	   else 
	     fprintf(stderr,"\nDigests not equal");
	
	   //Resetting the buffers
	   data[0] = '\0';
	   digest[0] = '\0';
	   recvData[0] = '\0';
	}

    //Close the file
	if(nc_args->verbose)
      printf("\n Closing the output file...");
    fclose(fp);

    //Close the socket
	if(nc_args->verbose)
      printf("\n Closing the Connection...");
    close(clientSock);
	fflush(stdout);
	
	/*printf("\n Do you want the server to be up and running?(y/n) ");
	fflush(stdout);
	scanf("%c", &runServ);
  }*/

  //Close the server socket
  if(nc_args->verbose)
    printf("\n Closing the server socket...");
  close(serverSock);
}

int main(int argc, char * argv[]){
  nc_args_t nc_args;

  //initializes the arguments struct for your use
  parse_args(&nc_args, argc, argv);

  if(nc_args.listen == 1){
    runServer(&nc_args);
	if(nc_args.verbose)
	  printf("\n Starting the Server...");
  }
  else{
    runClient(&nc_args);
	if(nc_args.verbose)
	  printf("\n Starting the Client...");
  }
  
  return 0;
}