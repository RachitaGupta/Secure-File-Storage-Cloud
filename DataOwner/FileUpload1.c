#include "common.h"
struct Index ind;
pairing_t pairing;
struct PublicKey PK;
struct PrivateKey PrivK;
struct Trapdoor trapdoor;

/**
* This is run by data owner to generate AES encryption key
*/
void SecretKeyGen(char* filename)
{
  char* a = "openssl rand -base64 128 -out ";
  char *result = malloc(strlen(a)+strlen(filename)+1);//+1 for the zero-terminator
  //in real code you would check for errors in malloc here
  if (result == NULL) exit (1);
  
  strcpy(result, a);
  strcat(result, filename);
  system(result);
}

/**
* This is run by data owner to encrypt an uploaded file
*/
void FileEncryption(char* PlaintextFile, char* KeyFile, char* CiphertextFile)
{
  char* a = "openssl enc -aes-256-cbc -salt -in ";
  char* b = malloc(strlen(a)+strlen(PlaintextFile)+1);
  if (b == NULL) exit (1);
  
  strcpy(b, a);
  strcat(b, PlaintextFile);
  
  char* a1 = " -out ";
  char* b1 = malloc(strlen(a)+strlen(CiphertextFile)+1);
  
  if (b1 == NULL) exit (1);
  
  strcpy(b1, a1);
  strcat(b1, CiphertextFile);
  
  char* b2 = malloc(strlen(b)+strlen(b1)+1);
  
  if (b2 == NULL) exit (1);
  
  strcpy(b2, b);
  strcat(b2, b1);
  
  char* a3 = " -pass file:./";
  char* b3 = malloc(strlen(a3)+strlen(KeyFile)+1);
  
  if (b3 == NULL) exit (1);
  
  strcpy(b3, a3);
  strcat(b3, KeyFile);
  
  char* result = malloc(strlen(b2)+strlen(b3)+1);
  strcpy(result, b2);
  strcat(result, b3);
  
  system(result);
  
}

/**
* This is the encryption algorithm of the ABE scheme
*/
void ABEEncrypt(int Policy[ ], element_t plaintext, struct ABECiphertext* abeciphertext)
{
  for(int i = 0; i < ATT_NUM; i++)
    abeciphertext->Policy[i] = Policy[i];
  
  element_init_GT(abeciphertext->C_hat, pairing);
  element_t s;
  element_init_Zr(s, pairing);
  element_random(s);
  
  element_t temp;
  element_init_GT(temp, pairing);
  element_pow_zn(temp, PK.Y, s);
  element_mul(abeciphertext->C_hat, plaintext, temp);
  
  element_init_G1(abeciphertext->C_prime, pairing);
  element_pow_zn(abeciphertext->C_prime, PK.g, s);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(Policy[i] == 1)
    {
      element_init_G1(abeciphertext->C[i], pairing);
      element_pow_zn(abeciphertext->C[i], PK.T[i], s);
    }
    if(Policy[i] == 2)
    {
      element_init_G1(abeciphertext->C[i], pairing);
      element_pow_zn(abeciphertext->C[i], PK.T[ATT_NUM+i], s);
    }
    if(Policy[i] == 0)
    {
      element_init_G1(abeciphertext->C[i], pairing);
      element_pow_zn(abeciphertext->C[i], PK.T[2*ATT_NUM+i], s);
    }
    
  }
  
  element_clear(temp);
}

/**
* This is run by data owner to encrypt an AES encryption key
* The ciphertext correponds to the second part stored in an index
*/
void ABEFileKeyEncrypt(char* KeyFile, int Policy[ ])
{
  //read the AES key stored in a file named KeyFile
  FILE *pFile=fopen(KeyFile,"r");
  char *Key;  
  fseek(pFile,0,SEEK_END); 
  int len=ftell(pFile); 
  Key=malloc(sizeof(char)*(len+1));
  rewind(pFile);
  fread(Key,1,len,pFile); 
  Key[len]=0;
  printf("%s\n", Key);
  fclose(pFile);
  
  //partition the symmetric key into two parts expKey1 and expKey2, so that they can be encrypted
  //by ABE algorithm
  unsigned char* expKey1 = malloc(sizeof(char)*129);
  for(int i = 0; i < 128; i++)
  {
    expKey1[i] = Key[i];
  }
  expKey1[128] = 0;
  printf("expkey1 is %s \n", expKey1);
  
  unsigned char* expKey2 = malloc(sizeof(char)*48);
  for(int i = 0; i < strlen(Key)-128; i++)
  {
    expKey2[i] = Key[128+i];
  }
  expKey2[47] = 0;
  printf("expkey2 is %s \n", expKey2);
  
  //covert expKey1 and expKey2 into pairing elements pbcKey1 and pbcKey2
  element_t pbcKey1;
  element_init_GT(pbcKey1, pairing);
  element_from_bytes(pbcKey1, expKey1);
  
  element_t pbcKey2;
  element_init_GT(pbcKey2, pairing);
  element_from_bytes(pbcKey2, expKey2);
  
  element_printf("pbcKey1 is %B\n", pbcKey1);
  element_printf("pbcKey2 is %B\n", pbcKey2);
  
  ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[0]);
  ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[1]);
  
}

/**
* This is run by data owner to genrate index for an uploaded file
*/
void SecureIndexGeneration(int Policy[], char* keywords[])
{
  ind.Keywords_Num = 1;
  element_t s;
  for(int i = 0; i < ATT_NUM; i++)
    ind.Policy[i] = Policy[i];
  
  element_init_Zr(s, pairing);
  element_random(s);
  
  element_init_G1(ind.D_hat, pairing);
  element_pow_zn(ind.D_hat, PK.g, s);
  
  element_init_GT(ind.D_prime, pairing);
  element_pow_zn(ind.D_prime, PK.Y, s);
  
  element_t temp;
  element_init_Zr(temp, pairing);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(i < ind.Keywords_Num)
    {
      if(Policy[i] == 1)
      {
        element_from_hash(temp, keywords[i], strlen(keywords[i]));
        element_div(temp, s, temp);
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[i], temp);
      }
      if(Policy[i] == 2)
      {
        element_from_hash(temp, keywords[i], strlen(keywords[i]));
        element_div(temp, s, temp);
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[ATT_NUM+i], temp);
      }
      if(Policy[i] == 0)
      {
        element_from_hash(temp, keywords[i], strlen(keywords[i]));
        element_div(temp, s, temp);
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[2*ATT_NUM+i], temp);
      }
    }
    
    if(i >= ind.Keywords_Num)
    {
      if(Policy[i] == 1)
      {
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[i], s);
      }
      if(Policy[i] == 2)
      {
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[ATT_NUM+i], s);
      }
      if(Policy[i] == 0)
      {
        element_init_G1(ind.D[i], pairing);
        element_pow_zn(ind.D[i], PK.T[2*ATT_NUM+i], s);
      }
      
    }
    
  }
  
  element_clear(temp);
  
}

int Search(struct Index ind, struct Trapdoor trapdoor)
{
  for(int i = 0; i < ATT_NUM; i++)
  {
    if((ind.Policy[i] == 1 && trapdoor.AttributeList[i] == 0) || (ind.Policy[i] == 2 && trapdoor.AttributeList[i] == 1))      
      return 2;
  }
  element_t temp;
  element_init_GT(temp, pairing);
  pairing_apply(temp, ind.D_hat, trapdoor.Q_hat, pairing);
  
  element_t temp1;
  element_init_GT(temp1, pairing);
  element_set1(temp1);
  
  element_t temp2;
  element_init_GT(temp2, pairing);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(ind.Policy[i] != 0)
    {
      pairing_apply(temp2, ind.D[i], trapdoor.Q[i], pairing);
      element_mul(temp1, temp1, temp2);
    }
    
    if(ind.Policy[i] == 0)
    {
      pairing_apply(temp2, ind.D[i], trapdoor.Qf[i], pairing);
      element_mul(temp1, temp1, temp2);
    }
  }
  
  element_mul(temp, temp, temp1);
  element_pow_zn(temp1, ind.D_prime, trapdoor.Q_prime);
  
  int search = 0;
  
  if(element_cmp(temp, temp1) == 0)
    search = 1;
  
  element_clear(temp1);
  element_clear(temp);
  element_clear(temp2);
  
  return search;
  
}

void TrapdoorGeneration(struct PrivateKey PrivK, char* keyword)
{
  element_t u;
  element_init_Zr(u,pairing);
  element_random(u);
  
  element_init_G1(trapdoor.Q_hat, pairing);
  element_pow_zn(trapdoor.Q_hat, PrivK.K_hat, u);
  
  element_init_Zr(trapdoor.Q_prime, pairing);
  //  element_add(trapdoor.Q_prime, u, PrivK.xf);
  element_set(trapdoor.Q_prime, u);
  
  element_t temp;
  element_init_Zr(temp, pairing);
  
  element_t KW;
  element_init_Zr(KW, pairing);
  element_from_hash(KW, keyword, strlen(keyword));
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(i == 0)
    {
      element_mul(temp, KW, u);
      element_init_G1(trapdoor.Q[i], pairing);
      element_pow_zn(trapdoor.Q[i], PrivK.K[i], temp);
      
      element_init_G1(trapdoor.Qf[i], pairing);
      element_pow_zn(trapdoor.Qf[i], PrivK.F[i], temp);
    }
    else
    {
      element_init_G1(trapdoor.Q[i], pairing);
      element_pow_zn(trapdoor.Q[i], PrivK.K[i], u);
      
      element_init_G1(trapdoor.Qf[i], pairing);
      element_pow_zn(trapdoor.Qf[i], PrivK.F[i], u);
    }
    
  }
  
}
void ABEDecrypt(struct ABECiphertext abeciphertext, element_t *m)
{
  //  element_printf("each ciphertext is %B\n", abeciphertext.C_hat);
  element_t temp;
  element_init_GT(temp, pairing);
  pairing_apply(temp, abeciphertext.C_prime, PrivK.K_hat, pairing);
  
  element_t temp1;
  element_init_GT(temp1, pairing);
  element_set1(temp1);
  
  element_t temp2;
  element_init_GT(temp2, pairing);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(abeciphertext.Policy[i] != 0)
    {
      pairing_apply(temp2, abeciphertext.C[i], PrivK.K[i], pairing);
      element_mul(temp1, temp1, temp2);
    }
    
    if(abeciphertext.Policy[i] == 0)
    {
      pairing_apply(temp2, abeciphertext.C[i], PrivK.F[i], pairing);
      element_mul(temp1, temp1, temp2);
    }
  }
  
  element_mul(temp, temp, temp1);
  
  element_div(temp1, abeciphertext.C_hat, temp);
  //  element_printf("temp1 is %B\n", temp1);
  
  element_set(*m, temp1);
  //  element_printf("m is %B\n", *m);
  
  // element_clear(temp1);
  element_clear(temp);
  element_clear(temp2);
  
}

void FileDecryption(char* CiphertextFile, char* KeyFile, char* PlaintextFile)//(FILE* file, int policy[ ])
{
  char* a = "openssl enc -d -aes-256-cbc -in ";
  char* b = malloc(strlen(a)+strlen(CiphertextFile)+1);
  if (b == NULL) exit (1);
  
  strcpy(b, a);
  strcat(b, CiphertextFile);
  
  char* a1 = " -out ";
  char* b1 = malloc(strlen(a)+strlen(PlaintextFile)+1);
  
  if (b1 == NULL) exit (1);
  
  strcpy(b1, a1);
  strcat(b1, PlaintextFile);
  
  char* b2 = malloc(strlen(b)+strlen(b1)+1);
  
  if (b2 == NULL) exit (1);
  
  strcpy(b2, b);
  strcat(b2, b1);
  
  char* a3 = " -pass file:./";
  char* b3 = malloc(strlen(a3)+strlen(KeyFile)+1);
  
  if (b3 == NULL) exit (1);
  
  strcpy(b3, a3);
  strcat(b3, KeyFile);
  
  char* result = malloc(strlen(b2)+strlen(b3)+1);
  strcpy(result, b2);
  strcat(result, b3);
  
  char* temp = "touch ";
  char* newfile = malloc(strlen(temp)+strlen(PlaintextFile)+1);
  strcpy(newfile, temp);
  strcat(newfile, PlaintextFile);
  
  system(newfile);
  system(result);
  
}

void ABEFileKeyDecrypt(struct ABEAESCiphertext abeaes, char* keyfilename)
{
  
  element_t* pbcKey1 = malloc(sizeof(element_t));
  element_t* pbcKey2 = malloc(sizeof(element_t));
  element_init_GT(*pbcKey1, pairing);
  element_init_GT(*pbcKey2, pairing);
  
  ABEDecrypt(abeaes.abeaesciphertext[0], pbcKey1);
  ABEDecrypt(abeaes.abeaesciphertext[1], pbcKey2);
  
  element_printf("pbcKey1 is %B\n", *pbcKey1);
  element_printf("pbcKey2 is %B\n", *pbcKey2);
  
  unsigned char temp1[129];
  unsigned char* data1 = temp1;
  element_to_bytes(data1, *pbcKey1);
  data1[128] = 0;
  
  printf("data1 is %s\n", data1);
  
  unsigned char* temp3 = malloc(sizeof(unsigned char)*176);
  
  //  strcpy(writekey, data1);
  
  printf("why?\n");
  for(int i = 0; i < 128; i++)
  {
    temp3[i] = data1[i];
    //   printf("%u, %u\n", temp3[i], data1[i]);
    
  }
  
  unsigned char temp2[48];
  unsigned char* data2 = temp2;
  element_to_bytes(data2, *pbcKey2);
  data2[47] = 0;
  
  printf("data2 is %s\n", data2);
  
  for(int i = 0; i < 47; i++)
  {
    temp3[128+i] = data2[i];
    //  printf("%u, %u\n", temp3[128+i], data2[i]);
  }
  
  temp3[175] = 0;
  printf("temp3 is %s\n", temp3);
  
  FILE *fp1;
  fp1 = fopen(keyfilename, "w");
  if(fp1 ==NULL)
    exit(1);
  
  fwrite(temp3, 1, strlen(temp3), fp1);
  fclose(fp1);
  
}

int main()
{
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  element_init_GT(PK.Y, pairing);
  element_init_G1(PK.g, pairing);
  for(int i = 0; i < PARAM_NUM; i++)
    element_init_G1(PK.T[i], pairing);
  
  readPKfromFile("PK.bin", &PK);
  
  int Policy[ATT_NUM];
  for(int i = 0; i < ATT_NUM; i++)
  {
    Policy[i] = 0;
  }
  Policy[0] = 1;
  Policy[1] = 0;
  
  //encrypt the keywords, AES key as well the files
  char* keywords[1] = {"ABE"};
  //generate the first part of the index
  SecureIndexGeneration(Policy, keywords);
  //encrypt the uploaded file
  SecretKeyGen("key.bin");
  FileEncryption("file.txt", "key.bin", "file.enc");
  //generate the second part of the index
  ABEFileKeyEncrypt("key.bin", Policy);
  
  /*
  //the first part of index
  unsigned char *Dhatstorage = malloc(65);
  unsigned char *Dprimestorage = malloc(128);
  unsigned char** Dstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Dstorage[i] = malloc(65);

  element_printf("ind.D_hat before transmission is %B\n", ind.D_hat);
  element_to_bytes_compressed(Dhatstorage, ind.D_hat);
  element_printf("ind.D_prime before transmission is %B\n", ind.D_prime);
  element_to_bytes(Dprimestorage, ind.D_prime);
  for(int i = 0; i < ATT_NUM; i++)
    element_printf("ind.D is %B\n", ind.D[i]);  
  for(int i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(Dstorage[i], ind.D[i]);
  
  //the second part of index
  unsigned char *C0hatstorage = malloc(128);
  unsigned char *C0primestorage = malloc(65);
  unsigned char** C0storage = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    C0storage[i] = malloc(65);
 
  element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_hat is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_hat);
  element_to_bytes(C0hatstorage, ind.abeaesciphertext.abeaesciphertext[0].C_hat);
  element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_prime is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_prime);
  element_to_bytes_compressed(C0primestorage, ind.abeaesciphertext.abeaesciphertext[0].C_prime);
  for(int i = 0; i < ATT_NUM; i++)
    element_printf("ind.abeaesciphertext.abeaesciphertext[0].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C[i]);  
  for(int i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(C0storage[i], ind.abeaesciphertext.abeaesciphertext[0].C[i]);                                
          
  unsigned char *C1hatstorage = malloc(128);
  unsigned char *C1primestorage = malloc(65);
  unsigned char** C1storage = malloc(sizeof(unsigned char*)*ATT_NUM);
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
 
 
 element_from_bytes_compressed(ind.D_hat, Dhatstorage);
 element_printf("Dhat %B\n", ind.D_hat);
 
 element_from_bytes(ind.D_prime, Dprimestorage);
 element_printf("Dprime %B\n", ind.D_prime);
 for(int i = 0; i < ATT_NUM; i++)
 {
   element_from_bytes_compressed(ind.D[i], Dstorage[i]);
   element_printf("ind.D[i] is %B\n", ind.D[i]);
 }
   
 element_from_bytes(ind.abeaesciphertext.abeaesciphertext[0].C_hat, C0hatstorage);
 element_printf("ind.abeaesciphertext.abeaesciphertext[0].Chat %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_hat);
 
 element_from_bytes_compressed(ind.abeaesciphertext.abeaesciphertext[0].C_prime, C0primestorage);
 element_printf("ind.abeaesciphertext.abeaesciphertext[0].C0prime %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_prime);
 for(int i = 0; i < ATT_NUM; i++)
 {
   element_from_bytes_compressed(ind.abeaesciphertext.abeaesciphertext[0].C[i], C0storage[i]);
   element_printf("ind.abeaesciphertext.abeaesciphertext[0].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C[i]);
 }
  
element_from_bytes(ind.abeaesciphertext.abeaesciphertext[1].C_hat, C1hatstorage);
 element_printf("ind.abeaesciphertext.abeaesciphertext[1].Chat %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_hat);
 
 element_from_bytes_compressed(ind.abeaesciphertext.abeaesciphertext[1].C_prime, C1primestorage);
 element_printf("ind.abeaesciphertext.abeaesciphertext[1].C0prime %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_prime);
 for(int i = 0; i < ATT_NUM; i++)
 {
   element_from_bytes_compressed(ind.abeaesciphertext.abeaesciphertext[1].C[i], C1storage[i]);
   element_printf("ind.abeaesciphertext.abeaesciphertext[1].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C[i]);
 }
   */
 
 element_init_G1(PrivK.K_hat, pairing);
 
 for(int i = 0; i < ATT_NUM; i++)
   element_init_G1(PrivK.K[i], pairing);
 
 for(int i = 0; i < ATT_NUM; i++)
   element_init_G1(PrivK.F[i], pairing);
 
 ReadPrivKfromFile("PrivK.bin", &PrivK);
 char* keyword = "ABE";
 
 TrapdoorGeneration(PrivK, keyword);
 for(int i = 0; i < ATT_NUM; i++)
   trapdoor.AttributeList[i] = 0;
 trapdoor.AttributeList[0] = 1;
 trapdoor.AttributeList[3] = 1;
 trapdoor.AttributeList[9] = 1;
 
 int search = Search(ind, trapdoor);
 
 if(search == 2)
   printf("you do not have the search capacity\n");
 else if( search == 1)
 {
   printf("yes, it contains the interested keyword\n");
   ABEFileKeyDecrypt(ind.abeaesciphertext, "DK.bin");
   FileDecryption("file.enc", "DK.bin", "decfile.txt");
 }
 else
   printf("no, it does not contain the interested keyword\n");
 
 
  return 0;
}








