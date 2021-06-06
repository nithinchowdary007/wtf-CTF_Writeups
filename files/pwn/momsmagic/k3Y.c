#include <stdio.h>

int main(){
	unsigned int ran;
	ran = rand();	

	unsigned int k=0;
	printf("Enter the Key: ");
	scanf("%d", &k);

	if( (k ^ ran) == 0xacedface ){
		printf("Yayy! U made it!\n");
		system("cat flag");
		return 0;
	}

	printf("Oops!, Best of luck with trying the other 2^32 cases.\n");
	return 0;
}
