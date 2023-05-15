#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_FILE "file_logging.log"
#define MAX_LINE_LEN 2000  // it is supposed that each line has no more than 

// if the condition is true, then the program prints the given message and exits
// returning error code
#define CHECK(cond, msg)  if(cond){ \
                              fprintf(stderr, "%s\n", msg); \
                              exit(1); \
                          }

struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	unsigned char *fingerprint; /* file fingerprint */
};

void *xmalloc(size_t size){
	void *ret_val = malloc(size);
	CHECK(ret_val == NULL, "Error allocating memory (malloc).");
	return ret_val;
}

void *xrealloc(void *ptr, size_t size){
	void *ret_val = realloc(ptr, size);
	CHECK(ret_val == NULL, "Error allocating memory (realloc).");
	return ret_val;
}

ssize_t mygetline(char **lineptr, FILE *stream){
	size_t n = MAX_LINE_LEN;
	int ret_val = getline(lineptr, &n, stream);
	if(ret_val != -1)
		(*lineptr)[ret_val-1] = '\0'; // throw the '\n' character

	return ret_val;
}

struct entry *read_log_file(int *len, FILE *log_file){
	struct entry *le = NULL; // every log entry

	char *file_line = xmalloc(MAX_LINE_LEN);
	int le_idx = -1;
	while(mygetline(&file_line, log_file) != -1){
		le_idx++;

		le = xrealloc(le, sizeof(struct entry) * (le_idx+1));

		struct entry *cur_le = le + le_idx;

		cur_le->uid = atoi(file_line);

		int len = mygetline(&file_line, log_file);
		cur_le->file = xmalloc(len);
		strcpy(cur_le->file, file_line);
		
		mygetline(&file_line, log_file);
		cur_le->date = cur_le->time = 0; // date and time are not needed

		mygetline(&file_line, log_file);
		cur_le->access_type = atoi(file_line);
		
		mygetline(&file_line, log_file);
		cur_le->action_denied = atoi(file_line);

		cur_le->fingerprint = xmalloc(16);
		unsigned char *c = cur_le->fingerprint; // used to make code shorter
		fscanf(log_file, "%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu ", 
				c, c+1, c+2, c+3, c+4, c+5, c+6, c+7, c+8, c+9, c+10, c+11, c+12, c+13, c+14, c+15);
	}

	*len = le_idx+1;

	return le;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	int le_len; // length of log entries
	struct entry *le = read_log_file(&le_len, log);

	// count for each user the number of the non authorized accesses

	typedef struct{
		uid_t usr;
		int num_of_accesses;
	} non_auth_acc_per_usr_t; // non authorized accesses per user

	non_auth_acc_per_usr_t *naapu = NULL;
	int naapu_len = 0;
	int naapu_idx;

	for(int i=0; i < le_len; i++){ // for each log entry
		naapu_idx = -1;
		for(int j=0; j < naapu_len; j++){ // search the user in naapu array
			if(naapu[j].usr == le[i].uid){
				naapu_idx = j; // user found
				break;
			}
		}

		if(naapu_idx == -1){
			// user not found in naapu array, create a node for him
			naapu = xrealloc(naapu, sizeof(non_auth_acc_per_usr_t) * (++naapu_len));
			naapu_idx = naapu_len-1;
			naapu[naapu_idx].usr = le[i].uid;
			naapu[naapu_idx].num_of_accesses = 0;
		}

		// if the action is denied for this user, then count it
		if(le[i].action_denied)
			naapu[naapu_idx].num_of_accesses++;
	}

	// now print the malicious users
	for(int i=0; i < naapu_len; i++){
		if(naapu[i].num_of_accesses > 7)
			printf("%d\n", naapu[i].usr);
	}

	return;
}

/**
 * Compares two fingerprints (16 bytes each). Returns 0 if they are equal, else
 * returns non-zero.
 */
int fingerprints_cmp(unsigned char *f1, unsigned char *f2){
	for(int i=0; i<16; i++){
		if(f1[i] != f2[i])
			return 1;
	}
	return 0;
}

void
list_file_modifications(FILE *log, char *file_to_scan)
{
	int le_len; // length of log entries
	struct entry *le = read_log_file(&le_len, log);

	char *pathname_to_scan = realpath(file_to_scan, NULL);
	if(pathname_to_scan == NULL){
		// if the path could not be resolved, then keep the path as is from the argument
		pathname_to_scan = xmalloc(strlen(file_to_scan)+1);
		strcpy(pathname_to_scan, file_to_scan);
	}

	typedef struct{
		uid_t usr;
		unsigned char **fingerprints;
		int fingerprints_len;
	} fingerprints_per_usr_t; // all the fingerprints for a user

	fingerprints_per_usr_t *fpu = NULL;
	int fpu_len = 0;
	int fpu_idx;

	for(int i=0; i < le_len; i++){ // for each log entry
		if(strcmp(le[i].file, pathname_to_scan) != 0)
			continue; // check only for the specified file

		fpu_idx = -1;
		for(int j=0; j < fpu_len; j++){ // search the user in fpu array
			if(fpu[j].usr == le[i].uid){
				fpu_idx = j; // user found
				break;
			}
		}

		if(fpu_idx == -1){
			// user not found in fpu array, create a node for him
			fpu = xrealloc(fpu, sizeof(fingerprints_per_usr_t) * (fpu_len++));
			fpu_idx = fpu_len-1;
			fpu[fpu_idx].usr = le[i].uid;
			fpu[fpu_idx].fingerprints_len = 0;
			fpu[fpu_idx].fingerprints = NULL;
		}

		// if the current fingerprint is not already in the fpu, then put it
		int fingerprint_exists = 0;
		for(int j=0; j < fpu[fpu_idx].fingerprints_len; j++){
			if(fingerprints_cmp(fpu[fpu_idx].fingerprints[j], le[i].fingerprint) == 0){
				fingerprint_exists = 1;
				break;
			}
		}

		if(!fingerprint_exists){
			// fingerprint not found, put it in array
			fpu[fpu_idx].fingerprints = xrealloc(fpu[fpu_idx].fingerprints, sizeof(char*) * (++fpu[fpu_idx].fingerprints_len));
			fpu[fpu_idx].fingerprints[fpu[fpu_idx].fingerprints_len-1] = le[i].fingerprint; // put it in the last position
		}
	}

	for(int i=0; i < fpu_len; i++){
		printf("User: %d\nModifications: %d\n\n", fpu[i].usr, fpu[i].fingerprints_len);
	}

	return;

}


int 
main(int argc, char *argv[])
{
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
