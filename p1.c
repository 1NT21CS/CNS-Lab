#include <stdio.h>
int main()
{
char str[] = "Hello World";
printf("Original string: %s\n\n", str);
printf("Bitwise AND operation: ");
for(int i=0;str[i]!='\0';i++){
str[i] = str[i] & 127;
printf("%c",str[i]);
}
printf("\n\n");
printf("Bitwise OR operation: ");
for(int i=0;str[i]!='\0';i++){
str[i] = str[i] | 127;
printf("%c",str[i]);
}
printf("\n\n");
printf("Bitwise XOR operation: ");
for(int i=0;str[i]!='\0';i++){
str[i] = str[i] ^ 127;
printf("%c",str[i]);
}
printf("\n\n");
return 0;
}
