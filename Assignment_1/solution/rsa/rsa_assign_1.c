#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

#define CTS 8 // ciphertext size (8 bytes of ciphertext for each byte of plaintext)

/**
 * Read a prime number from stdin (arbitrary number of digits).
 *   is_prime: A pointer to an integer. After the function call, *is_prime has
 *       the value: -1 if the user input was not a number, 0 if the user input
 *       number is non-prime, 1 if the user input number is probably prime
 *       (without being certain), 2 if the user input number is prime.
 *   The return value is a pointer to the user input.
 */
char *read_prime(int *is_prime);

/**
 * Perform RSA key-pair generation. The two primes are read from stdin.
 *   public_key_filepath: The path of the file to which the public key will be written.
 *   private_key_filepath: The path of the file to which the private key will be written.
 */
void g_option(char *public_key_filepath, char *private_key_filepath);

/**
 * Perform RSA decryption.
 *   input_filepath: The path of the file containing the ciphertext which will be decrypted.
 *   output_filepath: The path of the file to which the plaintext will be written.
 *   private_key_filepath: The path of the file which contains the private key.
 */
void d_option(char *input_filepath, char *output_filepath, char *private_key_filepath);

/**
 * Perform RSA encryption.
 *   input_filepath: The path of the file containing the plaintext which will be encrypted.
 *   output_filepath: The path of the file to which the ciphertext will be written.
 *   public_key_filepath: The path of the file which contains the public key.
 */
void e_option(char *input_filepath, char *output_filepath, char *public_key_filepath);



/*
 *
 */
int main(int argc, char *argv[]){

	char *input_filepath;
	char *output_filepath;
	char *key_filepath;

	// Parse command line options
	int opt;
	int opt_checker = 0; // Used to check which options where used
	while( (opt=getopt(argc, argv, "i:o:k:gdeh")) != -1 ){
		switch(opt){
			case 'i':
				input_filepath = strdup(optarg);
				opt_checker |= 1;
				break;
			case 'o':
				output_filepath = strdup(optarg);
				opt_checker |= 1<<1;
				break;
			case 'k':
				key_filepath = strdup(optarg);
				opt_checker |= 1<<2;
				break;
			case 'g':
				opt_checker |= 1<<3;
				break;
			case 'd':
				opt_checker |= 1<<4;
				break;
			case 'e':
				opt_checker |= 1<<5;
				break;
			case 'h':
			default:
				printf(
					"Options:\n"
					"-i path        Path to the input file\n"
					"-o path        Path to the output file\n"
					"-k path        Path to the key file\n"
					"-g             Perform RSA key-pair generation\n"
					"-d             Decrypt input and store results to output\n"
					"-e             Encrypt input and store results to output\n"
					"-h             This help message\n"
				);
				return 0;
		}
	}

	// Check that there is not a missing or an extra option
	// Initially, check that exactly one of the options -g, -d, -e has been invoked
	if( ((opt_checker>>3 & 0x1) + (opt_checker>>4 & 0x1) + (opt_checker>>5 & 0x1) != 1) ){
		fprintf(stderr, "Missing or extra option\n");
		exit(1);
	}else{
		// Now, check that if -d or -e has been invoked then -i, -o, -k have also been invoked
		if( (opt_checker>>4 & 0x1) == 1 || (opt_checker>>5 & 0x1) == 1 ){
			if( (opt_checker & 0x7) != 0x7 ){
				fprintf(stderr, "Missing or extra option\n");
				exit(1);
			}
		}
	}

	// Perform the appropriate functionality based on the user options
	if((opt_checker>>3 & 0x1) == 1){
		g_option("public.key", "private.key");
	}else if((opt_checker>>4 & 0x1) == 1){
		d_option(input_filepath, output_filepath, key_filepath);
	}else if((opt_checker>>5 & 0x1) == 1){
		e_option(input_filepath, output_filepath, key_filepath);
	}

	return 0;
}

/*
 *
 */
char *read_prime(int *is_prime){
	char *input=NULL;
	size_t buf_size=0;
	int str_len = getline(&input, &buf_size, stdin); // read from stdin
	input[str_len-1] = '\0'; // remove the '\n'

	// Convert the user input to mpz_t for primality check
	mpz_t p;
	int is_number = mpz_init_set_str(p, input, 10);

	if(is_number == -1){ // Check if it is a legitimate number
		*is_prime = -1;
	}else{
		// Primality check
		*is_prime = mpz_probab_prime_p(p, 40);
	}

	mpz_clear(p);

	return input;
}

/*
 *
 */
void g_option(char *public_key_filepath, char *private_key_filepath){
	puts("Give two prime numbers (each one followed by <CR>):");

	// Read the first prime
	int is_p_prime;
	char *p_str = read_prime(&is_p_prime);

	// Read the second prime
	int is_q_prime;
	char *q_str = read_prime(&is_q_prime);


	// Check primality
	switch(is_p_prime){
		case -1:
			fprintf(stderr, "The first input is not a number.\n");
			exit(1);
			break;
		case 0:
			fprintf(stderr, "The first number is not prime.\n");
			exit(1);
			break;
		case 1:
			fprintf(stderr, "The first number is probably not prime.\n");
			exit(1);
			break;

	}

	switch(is_q_prime){
		case -1:
			fprintf(stderr, "The second input is not a number.\n");
			exit(1);
			break;
		case 0:
			fprintf(stderr, "The second number is not prime.\n");
			exit(1);
			break;
		case 1:
			fprintf(stderr, "The second number is probably not prime.\n");
			exit(1);
			break;

	}

	// Convert the input primes to mpz_t
	mpz_t p, q;
	mpz_init_set_str(p, p_str, 10);
	mpz_init_set_str(q, q_str, 10);

	// Compute n
	mpz_t n;
	mpz_init(n);
	mpz_mul(n, p, q);

	// Compute lambda_n
	mpz_t lambda_n, p_minus_one, q_minus_one;
	mpz_inits(lambda_n, p_minus_one, q_minus_one, NULL);
	mpz_sub_ui(p_minus_one, p, 1);
	mpz_sub_ui(q_minus_one, q, 1);
	mpz_mul(lambda_n, p_minus_one, q_minus_one);
	
	// Initialize gmp random generator and seed
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	gmp_randseed_ui(rstate, time(NULL));

	// Choose a random prime e such that e%lambda_n!=0 and gcd(e, lambda_n)==1
	mpz_t e_tmp, e, twice_lambda_n, mod_result, gcd_result;
	mpz_inits(e_tmp, e, twice_lambda_n, mod_result, gcd_result, NULL);
	mpz_mul_ui(twice_lambda_n, lambda_n, 2);

	do{
		mpz_urandomm(e_tmp, rstate, twice_lambda_n); // Choose a random value to find its next prime (twice_lambda_n is an arbitrary ceil for the random number)
		mpz_nextprime(e, e_tmp);
		mpz_mod(mod_result, e, lambda_n);
		mpz_gcd(gcd_result, e, lambda_n);
	}while( !(mpz_cmp_ui(mod_result, 0) != 0 && mpz_cmp_ui(gcd_result, 1) == 0) );

	
	// Compute d
	mpz_t d;
	mpz_init(d);
	mpz_invert(d, e, lambda_n); 
	
	// Write the keys to the files
	char *n_str = mpz_get_str(NULL, 10, n);
	char *d_str = mpz_get_str(NULL, 10, d);
	char *e_str = mpz_get_str(NULL, 10, e);

	// Write the public key to the file
	FILE *out_file;
	out_file = fopen(public_key_filepath, "w");
	if(out_file==NULL){
		fprintf(stderr, "Opening public key file failure.\n");
		exit(1);
	}
	fprintf(out_file, "%s\n%s\n", n_str, e_str);
	fclose(out_file);

	// Write the private key to the file
	out_file = fopen(private_key_filepath, "w");
	if(out_file==NULL){
		fprintf(stderr, "Opening private key file failure.\n");
		exit(1);
	}
	fprintf(out_file, "%s\n%s\n", n_str, d_str);
	fclose(out_file);

	// Free unnecessary variables
	free(n_str);
	free(d_str);
	free(e_str);
	gmp_randclear(rstate);
	mpz_clears(p, q, lambda_n, p_minus_one, q_minus_one, e_tmp, twice_lambda_n, mod_result, gcd_result, n, d, e, NULL);
}

/*
 *
 */
void d_option(char *input_filepath, char *output_filepath, char *private_key_filepath){
	FILE *input_file, *output_file, *key_file;

	input_file = fopen(input_filepath, "r");
	output_file = fopen(output_filepath, "w");
	key_file = fopen(private_key_filepath, "r");

	if(input_file==NULL){
		fprintf(stderr, "Opening input file failure.\n");
		exit(1);
	}else if(output_file==NULL){
		fprintf(stderr, "Opening output file failure.\n");
		exit(1);
	}else if(key_file==NULL){
		fprintf(stderr, "Opening private key file failure.\n");
		exit(1);
	}

	// Read the private key from the file
	char *n_str=NULL, *d_str=NULL;
	size_t buf_size=0;
	int str_len;

	str_len = getline(&n_str, &buf_size, key_file); // read n from key file
	n_str[str_len-1] = '\0'; // remove the '\n'

	str_len = getline(&d_str, &buf_size, key_file); // read d from key file
	d_str[str_len-1] = '\0'; // remove the '\n'

	// Convert n, d to mpz
	mpz_t n, d;
	mpz_init_set_str(n, n_str, 10);
	mpz_init_set_str(d, d_str, 10);
	
	// Decrypt the file
	int ch;
	unsigned char ch_cipher[CTS];
	mpz_t m, c; 
	mpz_inits(m, c, NULL);

	while( fread(ch_cipher, sizeof ch_cipher[0], CTS, input_file) == CTS ){

		// Convert character array to mpz
		mpz_import(c, CTS, -1, sizeof ch_cipher[0], 0, 0, ch_cipher); 

		// Perform RSA decryption
		mpz_powm(m, c, d, n);
		
		// Convert from mpz to character
		ch = (int)mpz_get_ui(m);

		// Write the plaintext to the file
		fputc(ch, output_file);
	}

	fclose(input_file);
	fclose(output_file);
	fclose(key_file);
}

/*
 *
 */
void e_option(char *input_filepath, char *output_filepath, char *public_key_filepath){
	FILE *input_file, *output_file, *key_file;

	input_file = fopen(input_filepath, "r");
	output_file = fopen(output_filepath, "w");
	key_file = fopen(public_key_filepath, "r");

	if(input_file==NULL){
		fprintf(stderr, "Opening input file failure.\n");
		exit(1);
	}else if(output_file==NULL){
		fprintf(stderr, "Opening output file failure.\n");
		exit(1);
	}else if(key_file==NULL){
		fprintf(stderr, "Opening public key file failure.\n");
		exit(1);
	}

	// Read the public key from the file
	char *n_str=NULL, *e_str=NULL;
	size_t buf_size=0;
	int str_len;

	str_len = getline(&n_str, &buf_size, key_file); // read n from key file
	n_str[str_len-1] = '\0'; // remove the '\n'

	str_len = getline(&e_str, &buf_size, key_file); // read e from key file
	e_str[str_len-1] = '\0'; // remove the '\n'

	// Convert n, e to mpz
	mpz_t n, e;
	mpz_init_set_str(n, n_str, 10);
	mpz_init_set_str(e, e_str, 10);
	
	// Encrypt the file
	int ch;
	unsigned char ch_cipher[CTS];
	mpz_t m, c; 
	mpz_inits(m, c, NULL);

	while( (ch=fgetc(input_file)) != EOF ){

		// Convert character to mpz
		mpz_set_ui(m, ch);

		// Perform RSA encryption
		mpz_powm(c, m, e, n);
		
		// Convert from mpz to character array
		for(int i=0;i<CTS;i++) ch_cipher[i]=0; // Initialize to zeros
		mpz_export(ch_cipher, NULL, -1, sizeof ch_cipher[0], 0, 0, c); // By using -1 in the third argument it is specified that at the 0-indexed byte is the least
		                                                               // significant byte, hence the higher indexed bytes that are after the most significant byte
		                                                               // are zero-padded from the above initialization

		// Write the ciphertext to the file
		fwrite(ch_cipher, sizeof ch_cipher[0], CTS, output_file);
	}

	fclose(input_file);
	fclose(output_file);
	fclose(key_file);
}

