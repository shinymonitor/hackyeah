#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
//============================================
bool argument_is(int i, char* argument, int argc, char** argv);
bool file_exists(char* file_name);
bool rm_file(char* file_name);
bool rm_dir(char* dir_name);
bool ensure_dir(char* path);
bool copy_file(char* src, char* dest);
bool is_newer(char* file1, char* file2);
bool compile_if_changed(char* src, char* bin, char* command);
bool run_command(char* command);
bool fetch_to_lib(char* file_name, char* url);
bool fetch_to_lib_if_missing(char* file_name, char* url);
void print_info(char* message);
void print_error(char* message);
//============================================
#define COMMAND_MAX_LEN 512
bool argument_is(int i, char* argument, int argc, char** argv){
	if (argc<i+1) return false;
	return (strcmp(argv[i], argument)==0);
}
bool file_exists(char* file_name){
	FILE *file;
	if ((file = fopen(file_name, "r"))) {fclose(file); return true;}
	return false;
}
bool rm_file(char* file_name){
	if (!file_exists(file_name)) return false;
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "rm %s", file_name);
	return !system(command);
}
bool rm_dir(char* dir_name){
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "rm -rf %s", dir_name);
	return !system(command);
}
bool ensure_dir(char* path){
	if (file_exists(path)) return true;
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "mkdir -p %s", path);
	return !system(command);
}
bool copy_file(char* src, char* dest){
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "cp %s %s", src, dest);
	return !system(command);
}
static inline time_t get_mtime(char* filename) {
	struct stat st;
	if (stat(filename, &st) == -1) return 0;
	return st.st_mtime;
}
bool is_newer(char* file1, char* file2){return get_mtime(file1)>get_mtime(file2);}
bool run_command(char* command){return !system(command);}
bool compile_if_changed(char* src, char* bin, char* command){
	if (!is_newer(src, bin)) return true;
	return !system(command);
}
bool fetch_to_lib(char* file_name, char* url){
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "wget -q --show-progress %s -O lib/%s", url, file_name);
	return !system(command);
}
bool fetch_to_lib_if_missing(char* file_name, char* url){
	char full_path[COMMAND_MAX_LEN];
	snprintf(full_path, sizeof(full_path), "lib/%s", file_name);
	if(file_exists(full_path)) return true;
	char command[COMMAND_MAX_LEN];
	snprintf(command, sizeof(command), "wget -q --show-progress %s -O lib/%s", url, file_name);
	return !system(command);
}
void print_info(char* message){printf("[INFO] %s\n", message);}
void print_error(char* message){printf("\x1B[31;1;4m[ERROR] %s\n\x1B[0m", message);}
