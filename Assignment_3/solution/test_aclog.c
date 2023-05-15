#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", "file_2", "file_3", 
							"file_4", "file_5", "file_6", "file_7", 
							"file_8", "file_9"};

	// create file_3 (if it doesn't exit)
	file = fopen(filenames[3], "w");
	
	if(file!=NULL)
		fclose(file);

	// test "r"
	for (i = 0; i < 4; i++) {
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error in file \"%s\"\n", filenames[i]);
		else
			fclose(file);
	}

	// test "a+" in file_2 (make many writes)
	file = fopen(filenames[2], "a+");
	if (file == NULL) 
		printf("fopen error in file \"%s\"\n", filenames[i]);
	
	char *to_write = "demo write\n";
	bytes = fwrite(to_write, strlen(to_write), 1, file);

	to_write = "demo write again\n";
	bytes = fwrite(to_write, strlen(to_write), 1, file);

	to_write = "and again\n";
	bytes = fwrite(to_write, strlen(to_write), 1, file);

	to_write = "...and again\n";
	bytes = fwrite(to_write, strlen(to_write), 1, file);

	fclose(file);

	// trying to write in file_0 without authorization
	file = fopen(filenames[0], "r+");
	if (file == NULL) 
		printf("fopen error in file \"%s\"\n", filenames[i]);
	// it won't open


	// trying to be malicious
	file = fopen(filenames[0], "r+");
	file = fopen(filenames[1], "r+");
	file = fopen(filenames[2], "r+");
	file = fopen(filenames[3], "r+");
	file = fopen(filenames[4], "r+");
	file = fopen(filenames[5], "r+");
	file = fopen(filenames[6], "r+");
	file = fopen(filenames[7], "r+");
	file = fopen(filenames[8], "r+");
	file = fopen(filenames[9], "r+");

	return 0;
}
