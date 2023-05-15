#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include <limits.h>

#define LOG_FILE "file_logging.log"

typedef struct {
	uid_t uid;
	char *filename;
	char *date_time;
	int access_type;
	int is_action_denied;
	unsigned char file_fingerprint[MD5_DIGEST_LENGTH];
} log_entry_t;

/**
 * Tests if str matches the (extended) regular expression regex.
 * If it matches, it returns 0, else it returns non-zero.
 */
int regex(const char *str, char *regex){
	regex_t preg;
	regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB);
	int ret_val = regexec(&preg, str, 0, NULL, 0); 
	regfree(&preg);
	return ret_val;
}

int md5_hash_file(const char *pathname, unsigned char *md){
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(pathname, "r");

	if(original_fopen_ret == NULL)
		return -1;

	struct stat file_status;
	if(stat(pathname, &file_status) != 0)
		return -2;

	void *file_content = malloc(file_status.st_size);
	if(file_content == NULL)
		return -3;

	fread(file_content, 1, file_status.st_size, original_fopen_ret);
	
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, file_content, file_status.st_size);
	MD5_Final(md, &md5_ctx);

	free(file_content);

	return 0;
}


void write_log_entry(const log_entry_t *le){
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(LOG_FILE, "a");

	// convert file_fingerprint to a string of decimal digits
	char file_fingerprint_str[4*MD5_DIGEST_LENGTH] = {0}; // 3 (or less) decimal digits (0-255) and a space for each file_fingerprint element

	int str_idx = 0;
	for(int digit_idx=0; digit_idx < MD5_DIGEST_LENGTH; digit_idx++){
		str_idx += sprintf(file_fingerprint_str+str_idx, "%d ", le->file_fingerprint[digit_idx]);
	}

	// log
	fprintf(original_fopen_ret, "%d\n%s\n%s%d\n%d\n%s\n\n", le->uid, le->filename, le->date_time, le->access_type, le->is_action_denied, file_fingerprint_str);

	fclose(original_fopen_ret);
}

FILE *
fopen(const char *path, const char *mode) 
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	// create the log entry
	log_entry_t le;

	// get the UID
	le.uid = getuid();

	// get the filename
	le.filename = realpath(path, NULL); // get the full pathname
	if(le.filename == NULL){
		// if the path could not be resolved, then keep the path as is from the argument
		le.filename = malloc(strlen(path)+1);
		if(le.filename == NULL){
			fprintf(stderr, "malloc error.\n");
			exit(1);
		}

		strcpy(le.filename, path);
	}
	
	// get date and time
	time_t t = time(NULL);
	le.date_time = ctime(&t);

	// get access type
	int mode_r = !regex(mode, "^(b?r|rb)$");
	int mode_r_plus = !regex(mode, "^(b?r\\+|rb\\+|r\\+b)$");
	int mode_w = !regex(mode, "^(b?w|wb)$");
	int mode_w_plus = !regex(mode, "^(b?w\\+|wb\\+|w\\+b)$");
	int mode_a = !regex(mode, "^(b?a|ab)$");
	int mode_a_plus = !regex(mode, "^(b?a\\+|ab\\+|a\\+b)$");
	int file_exists = access(path, F_OK) != 0;

	le.access_type = -1; // illegal access_type (in case of invalid mode)

	if(mode_w || mode_w_plus || mode_a || mode_a_plus){
		if(!file_exists){
			// file does not exist
			// file creation
			le.access_type = 0;
		}else{
			// file exists
			// file open
			le.access_type = 1;
		}
	}else if(file_exists && (mode_r || mode_r_plus)){
		// file exists
		// file open
		le.access_type = 1;
	}

	// check if action is denied
	if(original_fopen_ret == NULL && errno == EACCES)
		le.is_action_denied = 1;
	else
		le.is_action_denied = 0;

	// create file fingerprint
	md5_hash_file(path, le.file_fingerprint);

	// write to the log file
	write_log_entry(&le);

	// free the filename from le
	free(le.filename);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	// create the log entry
	log_entry_t le;

	// get the UID
	le.uid = getuid();

	// get the filename
	char proclink[200];
	sprintf(proclink, "/proc/self/fd/%d", fileno(stream));
	char pathname[2000];
	int pathname_len = readlink(proclink, pathname, 2000);
	if(pathname_len == -1)
		le.filename = "//// ERROR PATH ////";
	else{
		pathname[pathname_len] = '\0';
		le.filename = pathname;
	}
	
	// get date and time
	time_t t = time(NULL);
	le.date_time = ctime(&t);

	// access type
	le.access_type = 2; // write

	// check if action is denied
	if(original_fwrite_ret == 0) // if fwrite did not write any bytes, then set the action denied flag
		le.is_action_denied = 1;
	else
		le.is_action_denied = 0;

	// create file fingerprint
	fflush(stream); // flush the data to the file before hashing its value
	md5_hash_file(pathname, le.file_fingerprint);

	// write to the log file
	write_log_entry(&le);

	return original_fwrite_ret;
}


