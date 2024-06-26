#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
void printVigenereTable()
{
printf("Vigenere Table ");
printf("A B C D E F G H I J K L M N O P Q R S T U V W X Y Z \n");
for(int i = 0; i < 26; i++){
printf("%c", 'A' + i);
for(int j = 0; j < 26; j++){
printf("%c", 'A' + (i + j) % 26);
}
printf("\n");
}
}
void encrypt()
{
char plaintext[128];
char key[16];
printf("Enter the plain text: ");
scanf(" %[^\n]", plaintext);
getchar();
printf("Enter the key: ");
scanf(" %[^\n]", key);
getchar();
printf("Cipher text is: ");
for(int i = 0, j = 0; i < strlen(plaintext); i++, j++){
if(j >= strlen(key)){
j = 0;
}
int shift = toupper(key[j]) - 'A';
char encryptChar = ((toupper(plaintext[i]) - 'A' + shift) % 26) + 'A';
printf("%c", encryptChar);
}
printf("\n");
}
void decrypt()
{
char ciphertext[128];
char key[16];
printf("Enter the chipher text; ");
scanf(" %[^\n]", ciphertext);
getchar();
printf("Enter the key: ");
scanf(" %[^\n]", key);
getchar();
printf("decrypted text: ");
for(int i=0, j=0; i < strlen(ciphertext); i++, j++){
if(j >= strlen(key)){
j = 0;
}
int shift = toupper(key[j]) - 'A';
char decryptChar = ((toupper(ciphertext[i]) - 'A' - shift + 26) % 26) + 'A';
printf("%c", decryptChar);
}
printf("\n");
}
int main() {
int option;
while (1) {
printf("\n1. Encrypt");
printf("\n2. Decrypt");
printf("\n3. Print Vigenère Table");
printf("\n4. Exit\n");
printf("\nEnter your option: ");
scanf("%d", &option);
switch (option) {
case 1:
encrypt();
break;
case 2:
decrypt();
break;
case 3:
printVigenereTable();
break;
case 4:
exit(0);
default:
printf("\nInvalid selection! Try again.\n");
break;
}
}
return 0;
}