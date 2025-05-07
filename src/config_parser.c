#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_parser.h"
// actual implementation to read config

FirewallConfig load_config(const char *filname){
	FirewallConfig config;
	FILE *fp = fopen(filename, "r");
	if(!fp){
		perror("config file open failed");
		exit(1);
	}
	
	// initial
	strcpy(config.blacklist_file, "blacklist.txt");
	config.queue_num =0; 
	config.log_mode = 0;
	
	char line[256];
	while(fgets(line, sizeof(line), fp)){
		char *key = strtok(line, "="); //what is this finction
		char *value = strtok(NULL, "\n");
		
		if (strcmp(key, "blacklist_file") == 0) {
			strncpy(config.blacklist_file, value, sizeof(config.blacklist_file));
			
		} else if (strcmp(key, "queue_num") == 0)){
			config.queue_num = atoi(value);
		} else if (strcmp(key, "log_mode") == 0)){
			if(strcmp(value, "verbose") == 0){
				config.log_mode = 1;
			} else {
				config.log_mode = 0;
			}
		}
		
	}
	fclose(fp);
    return config;
	
	
}

