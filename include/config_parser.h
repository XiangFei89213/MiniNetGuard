#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H
// read the config file


// save the structure of config filr
typedef struct {
    char blacklist_file[128];
    int queue_num;
    int log_mode; // 0 = silent, 1 = verbose
} FirewallConfig;

// what function have for this FIrewallConfig, 
FirewallConfig load_config(const char *filename);

#endif
