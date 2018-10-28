
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define Nb 4


  long int rani[1048576][16];
 unsigned int final[1048576][16];
 unsigned char temp2[16];
   unsigned char enc[1048576][16];

// The number of rounds in AES Cipher. It is simply initiated to zero. The actual value is recieved in the program.
int Nr=0;

// The number of 32 bit words in the key. It is simply initiated to zero. The actual value is recieved in the program.
int Nk=0;

// in - it is the array that holds the CipherText to be decrypted.
// out - it is the array that holds the output of the for decryption.
// state - the array that holds the intermediate results during decryption.
unsigned char in[16], out[16], state[4][4];
unsigned int  a[16777220];
// The array that stores the round keys.
unsigned char RoundKey[240];

// The Key input to the AES Program
unsigned char Key[32];
void KeyExpansion();
void Cipher();
void Test_Distribution_of_Bytes_UD(unsigned int X[], unsigned int Size);
void Test_Distribution_of_Bytes_Pair(unsigned int X[], unsigned int Size);

unsigned char temp[16] = {0x0 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0 ,0x0 ,0x0 ,0x00 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0};
//	unsigned char temp2[16]= {01 , 0xaf ,0x01 ,0x01 ,0x01 ,0x01, 0x11 ,0x01 ,0x01 ,0x06 ,0x01 ,0x61 ,0x51, 0x91 ,0x91};

	unsigned char Save_Enc_Unchanged[16];
	unsigned char Save_Enc_Key[16][16];
	unsigned char Save_Enc_Plaintext[16][16];
	
FILE *fptr, *fptr1, *fptr2;
int getSBoxValue(int num)
{
	int sbox[256] =   {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	return sbox[num];
}

// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
int Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };
	
	
int main()
{
	int i,j;

//	// Recieve the length of key here.
//	while(Nr!=128 && Nr!=192 && Nr!=256)
//	{
//		printf("Enter the length of Key(128, 192 or 256 only): ");
//		scanf("%d",&Nr);	}
//	// Calculate Nk and Nr from the recieved value.
//	Nk = Nr / 32;
//	Nr = Nk + 6;

	Nk = 4;
	Nr = 10;
	
//--------------------------------------------------random input ------------------------------------------------------------------------


  long int ctr,k;
  srand ( time(NULL) );
 for(ctr=0;ctr<=1048576;ctr++)// to increase trials  4096
 {

 
 printf("\n------------------------- try number%d------------------------\n",ctr);
 
		for(j=0;j<16;j++){
         int iSecret;
         iSecret = rand() % 256 + 1;
         rani[ctr][j]=iSecret;
        temp2[j] = rani[ctr][j];
   }
  

	// Copy the Key and PlainText
	for(i=0;i<Nk*4;i++)
	{
		Key[i]=temp[i];
		in[i]=temp2[i];
	}
//printf("\nYour Plain Text is:\n");
//	for(i=0;i<Nk*4;i++)
//	{
//		printf("%x ",in[i]);
//	}
	
//	printf("\n\n");
		
//	printf("\nYour key Text is:\n");
//	for(i=0;i<Nk*4;i++)
//	{
//		printf("%x ",Key[i]);
//	}

	// The KeyExpansion routine must be called before encryption.
	KeyExpansion();

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher();


	// Output the encrypted text.
////	printf("\nYour message encrypted:\n");
	for(i=0;i<Nk*4;i++)
	{
	enc[ctr][i]=out[i];
//	printf("%x ",enc[ctr][i]);
	final[ctr][i] = enc[ctr][i];
		// a[i]=(unsigned int ) out [i];// to get che square value 1
//	printf("%d ,",final[ctr][i]);
	}
}

 for(int x=0;x<=1048576;x++)// to increase trials  4096
 {

	for(int y=0;y<16;y++){
	 	int position = x*16 + y;
		a[position] = final[x][y];
	//	printf("%d ,",a[position]);  // Encrypted data in 1D(decimal)

}
}
fptr = fopen("SRP.txt","w");


 for(int z=0; z<16777216; z++)
 	fprintf(fptr,"%d\n", a[z]);	
 
fclose(fptr);	   
Test_Distribution_of_Bytes_UD(a , 256*256*256);
Test_Distribution_of_Bytes_Pair	(a , 256*256*256);
}

//=======================================================Enc===============================================================

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to encrypt the states. 
void KeyExpansion()
{
	int i,j;
	unsigned char temp[4],k;
	
	// The first round key is the key itself.
	for(i=0;i<Nk;i++)
	{
		RoundKey[i*4]=Key[i*4];
		RoundKey[i*4+1]=Key[i*4+1];
		RoundKey[i*4+2]=Key[i*4+2];
		RoundKey[i*4+3]=Key[i*4+3];
	}

	// All other round keys are found from the previous round keys.
	while (i < (Nb * (Nr+1)))
	{
					for(j=0;j<4;j++)
					{
						temp[j]=RoundKey[(i-1) * 4 + j];
					}
					if (i % Nk == 0)
					{
						// This function rotates the 4 bytes in a word to the left once.
						// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

						// Function RotWord()
						{
							k = temp[0];
							temp[0] = temp[1];
							temp[1] = temp[2];
							temp[2] = temp[3];
							temp[3] = k;
						}

						// SubWord() is a function that takes a four-byte input word and 
						// applies the S-box to each of the four bytes to produce an output word.

						// Function Subword()
						{
							temp[0]=getSBoxValue(temp[0]);
							temp[1]=getSBoxValue(temp[1]);
							temp[2]=getSBoxValue(temp[2]);
							temp[3]=getSBoxValue(temp[3]);
						}

						temp[0] =  temp[0] ^ Rcon[i/Nk];
					}
					else if (Nk > 6 && i % Nk == 4)
					{
						// Function Subword()
						{
							temp[0]=getSBoxValue(temp[0]);
							temp[1]=getSBoxValue(temp[1]);
							temp[2]=getSBoxValue(temp[2]);
							temp[3]=getSBoxValue(temp[3]);
						}
					}
					RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0];
					RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1];
					RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2];
					RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3];
					i++;
	}
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(int round) 
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes()
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[i][j] = getSBoxValue(state[i][j]);

		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows()
{
	unsigned char temp;

	// Rotate first row 1 columns to left	
	temp=state[1][0];
	state[1][0]=state[1][1];
	state[1][1]=state[1][2];
	state[1][2]=state[1][3];
	state[1][3]=temp;

	// Rotate second row 2 columns to left	
	temp=state[2][0];
	state[2][0]=state[2][2];
	state[2][2]=temp;

	temp=state[2][1];
	state[2][1]=state[2][3];
	state[2][3]=temp;

	// Rotate third row 3 columns to left
	temp=state[3][0];
	state[3][0]=state[3][3];
	state[3][3]=state[3][2];
	state[3][2]=state[3][1];
	state[3][1]=temp;
}

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// MixColumns function mixes the columns of the state matrix
void MixColumns()
{
	int i;
	unsigned char Tmp,Tm,t;
	for(i=0;i<4;i++)
	{	
		t=state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ;
		Tm = state[0][i] ^ state[1][i] ; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp ;
		Tm = state[1][i] ^ state[2][i] ; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp ;
		Tm = state[2][i] ^ state[3][i] ; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp ;
		Tm = state[3][i] ^ t ; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp ;
	}
}

// Cipher is the main function that encrypts the PlainText.
void Cipher()
{
	int i,j,round=0;

	//Copy the input PlainText to state array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[j][i] = in[i*4 + j];
		}
	}

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0); 
	
	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for(round=1;round<Nr;round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	
	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);

	// The encryption process is over.
	// Copy the state array to output array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			out[i*4+j]=state[j][i];
		}
	}
}





void Test_Distribution_of_Bytes_UD(unsigned int X[], unsigned int Size)
{
	

			unsigned int i = 0;
            unsigned int Count_Distribution[256];
            double Expected_Value = 0.0;
            double Chi_Square_N = 0.0;
            
            for (i = 0; i < 256; i++)
            {
                Count_Distribution[i] = 0;     
            }
     
            for (i = 0; i < Size; i++)
            {
				Count_Distribution[X[i]]++;
            }
            
			fptr1 = fopen("SRP1.txt","a");

 				for(int z1=0; z1<256; z1++)
 				fprintf(fptr1,"%d\n", Count_Distribution[z1]);	
 			fclose(fptr1);
 			
 			
 			
            Expected_Value = (double)(Size) / 256;

//             for (i = 0; i < 256; i++)
//            {
//               // printf("%d ",Count_Distribution[i]);     
//            }
			printf("\n\n");
                
            for (i = 0; i < 256; i++)
            {
                Chi_Square_N += (( ((double)(Count_Distribution[i])) - Expected_Value) * ( ((double)(Count_Distribution[i])) - Expected_Value)) / Expected_Value;
            }

            //Chi Square (Variance)
            Chi_Square_N = Chi_Square_N / 256;


            //Mean Value
            double MW = 0;
            double Sum = 0;
            for (i = 1; i < 256; i++)
            {
                MW = MW + ((double)(Count_Distribution[i])) * i;
                Sum = Sum + (double)(Count_Distribution[i]);
            }

            MW = MW / Sum;

            
 			 printf("Testing using uniform Distribution\n");
            printf("Chi Square (Variance) = %#g\n", Chi_Square_N);
            printf("Mean Value = %#g\n", MW);
            printf("Expected Count = %#g\n", Expected_Value);
        
            

}
  

void Test_Distribution_of_Bytes_Pair(unsigned int X[], unsigned int Size)
{
			unsigned int i = 0;
            unsigned int Count_Distribution_Pair[256];
            double Expected_Value = 0.0;
            double Chi_Square_N_Pair = 0.0;
            
            for (i = 0; i < 256; i++)
            {
                Count_Distribution_Pair[i] = 0;     
            }
     		for ( i = 0; i < Size-2; i++)
            {
                if (X[i] == X[i + 1] && X[i + 1] != X[i + 2])
                {
                    Count_Distribution_Pair[X[i]]++;
                }
            }

			fptr2 = fopen("SRP2.txt","a");

 				for(int z2=0; z2<256; z2++)
 				fprintf(fptr2,"%d\n", Count_Distribution_Pair[z2]);
 				
 			fclose(fptr2);	
 			
 			
            Expected_Value = (double)(Size) / (256*256);

//             for (i = 0; i < 256; i++)
//            {
//               // printf("%d ",Count_Distribution[i]);     
//            }
			printf("\n\n");
                
            for (i = 0; i < 256; i++)
            {
                Chi_Square_N_Pair += (( ((double)(Count_Distribution_Pair[i])) - Expected_Value) * ( ((double)(Count_Distribution_Pair[i])) - Expected_Value)) / Expected_Value;
            }

            //Chi Square (Variance)
            Chi_Square_N_Pair = Chi_Square_N_Pair / 256;


            //Mean Value
            double MW = 0;
            double Sum = 0;
            for (i = 1; i < 256; i++)
            {
                MW = MW + ((double)(Count_Distribution_Pair[i])) * i;
                Sum = Sum + (double)(Count_Distribution_Pair[i]);
            }

            MW = MW / Sum;

            
 			printf("Testing using Pair Test\n");
            printf("Chi Square (Variance) = %#g\n", Chi_Square_N_Pair);
            printf("Mean Value = %#g\n", MW);
            printf("Expected Count = %#g\n", Expected_Value);
        
            

}
  
