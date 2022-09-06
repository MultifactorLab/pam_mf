typedef struct mf_config {
	char			hosts[300];
	char			port[100];
	char			secret[300];
	char			nas[300];
	char			users[300];
	char			groups[300];
	int			skipLocal;
	int			timeout;
	int			retry;
	int			rAlways,rUser,rSkip,rBypass,rInt,rOk,rFail;
} mf_config_t;

void initConfig(mf_config_t* cfg);
void dumpConfig(mf_config_t* cfg);
int loadConfig(mf_config_t* cfg, char* file, char* service);
void mfLog(const char* p_format, ...);
int getItem(char* items, int idx, char* res);


