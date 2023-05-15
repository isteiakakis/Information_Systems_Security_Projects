#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>

/**
 * Perform the Diffie-Hellman key exchange.
 *   output_filepath: The filepath to which the output will be written
 *   p: Prime number.
 *   g: Primitive root of the above prime number (it is not necessary
 *       to be a primitive root, but it is safer for cryptanalysis to be).
 *   a: Private key of user A.
 *   b: Private key of user B.
 */
void perform_dh(char *output_filepath, mpz_t p, mpz_t g, mpz_t a, mpz_t b);



/*
 *
 */
int main(int argc, char *argv[]){

	char *output_filepath; // The filepath to which the output will be written
	mpz_t p; // Prime number
	mpz_t g; // Primitive root of the above prime number
	mpz_t a; // Private key of user A
	mpz_t b; // Private key of user B

	mpz_inits(p, g, a, b, NULL);

	// Parse command line options
	int opt;
	int opt_checker = 0; // Used to check which options where used
	while( (opt=getopt(argc, argv, "o:p:g:a:b:h")) != -1 ){
		switch(opt){
			case 'o':
				output_filepath = strdup(optarg);
				opt_checker |= 1;
				break;
			case 'p':
				mpz_set_str(p, optarg, 10);
				opt_checker |= 1<<1;
				break;
			case 'g':
				mpz_set_str(g, optarg, 10);
				opt_checker |= 1<<2;
				break;
			case 'a':
				mpz_set_str(a, optarg, 10);
				opt_checker |= 1<<3;
				break;
			case 'b':
				mpz_set_str(b, optarg, 10);
				opt_checker |= 1<<4;
				break;
			case 'h':
			default:
				printf(
					"Options:\n"
					"-o path        Path to output file\n"
					"-p number      Prime number\n"
					"-g number      Primitive Root for previous prime number\n"
					"-a number      Private key A\n"
					"-b number      Private key B\n"
					"-h             This help message\n"
				);
				return 0;
		}
	}

	// Check that there is not a missing option
	if(opt_checker != 0x1F){
		fprintf(stderr, "Missing option\n");
		exit(1);
	}

	// Check primality of p
	int is_p_prime = mpz_probab_prime_p(p, 40);
	if(is_p_prime == 0 || is_p_prime == 1){
		fprintf(stderr, "p is (probably) not prime.\n");
		exit(1);
	}

	// Perform Diffie-Hellman key exchange
	perform_dh(output_filepath, p, g, a, b);

	// Clear the mpz variables
	mpz_clears(p, g, a, b, NULL);
	
	return 0;
}

/*
 *
 */
void perform_dh(char *output_filepath, mpz_t p, mpz_t g, mpz_t a, mpz_t b){
	mpz_t A; // This is sent from user A to user B
	mpz_t B; // This is sent from user B to user A
	mpz_t s1, s2; // Shared secret (those must be equal)

	mpz_inits(A, B, s1, s2, NULL);

	// User A side
	mpz_powm(A, g, a, p); // This is going to be sent to user B publicly

	// User B side
	mpz_powm(B, g, b, p); // This is going to be sent to user A publicly

	// User A side
	mpz_powm(s1, B, a, p); // Compute the shared secret

	// User B side
	mpz_powm(s2, A, b, p); // Compute the shared secret

	// Verify that the shared secret that user A and user B shared is the same
	if(mpz_cmp(s1, s2) != 0){
		printf("Problem: The shared secret is different.\n");
	}

	// Convert every mpz to string (except s2 which is equal to s1) and then clear every mpz
	char *A_str = mpz_get_str(NULL, 10, A);
	char *B_str = mpz_get_str(NULL, 10, B);
	char *s1_str = mpz_get_str(NULL, 10, s1);

	mpz_clears(A, B, s1, s2, NULL);

	// Write to the output file
	FILE *out_file;
	out_file = fopen(output_filepath, "w");
	if(out_file==NULL){
		fprintf(stderr, "Opening output file failure.\n");
		exit(1);
	}

	fprintf(out_file, "%s, %s, %s", A_str, B_str, s1_str);

	free(A_str);
	free(B_str);
	free(s1_str);
	
	fclose(out_file);
}
