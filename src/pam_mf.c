#include "radius.h"
#include "config.h"
#include "service.h"
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	char user[100];
	user[0]=0;
	char service[100];
	service[0]=0;
	char host[100];
	service[0]=0;
	char clientId[100];
	service[0]=0;
	char password[100];
	password[0]=0;

	char *buf;
	char *resp=NULL;
	mf_config_t cfg;
	initConfig(&cfg);
        char config[100];
        if(argc>0) strcpy(config,argv[0]);
	else strcpy(config,"/etc/pam_mf.conf");
	loadConfig(&cfg,config,NULL);
       	retval = pam_get_item(pamh, PAM_SERVICE,(const void**)&buf);
        if (retval == PAM_SUCCESS && buf!=NULL) {
		strncpy(service,buf,sizeof(service)-1);
		loadConfig(&cfg,config,service);
		if(strcmp(service,"sshd")==0) {
			retval = pam_prompt(pamh,PAM_TEXT_INFO,&resp,"%s"," ");
			if (retval != PAM_SUCCESS || resp!=NULL ) strcpy(service,"sshd_password");
			else strcpy(service,"sshd_interactive");
			loadConfig(&cfg,config,service);
		}
	}
	//dumpConfig(&cfg);
	if(cfg.rAlways!=-1) return cfg.rAlways;
        retval = pam_get_item(pamh, PAM_USER,(const void**)&buf);
        if (retval == PAM_SUCCESS && buf!=NULL) strncpy(user,buf,sizeof(user)-1);
	if(strlen(user)==0) return cfg.rUser!=-1?cfg.rUser:PAM_USER_UNKNOWN;
	if(findItem(user,cfg.users)>=0)  return cfg.rSkip!=-1?cfg.rSkip:PAM_SUCCESS;
	retval=chkUser(user,cfg.groups);
        if(retval>0) return cfg.rSkip!=-1?cfg.rSkip:PAM_SUCCESS;
	if(retval==0 && cfg.skipLocal) return cfg.rSkip!=-1?cfg.rSkip:PAM_SUCCESS;
        if(cfg.passRequired) {
	        retval = pam_get_item(pamh, PAM_AUTHTOK,(const void**)&buf);
        	if (retval == PAM_SUCCESS && buf!=NULL) strncpy(password,buf,sizeof(password)-1);
		if(strlen(password)==0) {
			retval = pam_prompt(pamh,PAM_PROMPT_ECHO_OFF,&resp,"%s: ","Password");
			if (retval == PAM_SUCCESS && resp!=NULL ) {
 				strncpy(password,resp,sizeof(password)-1);
				pam_set_item(pamh, PAM_AUTHTOK, password);
			}
		}
	}
        retval = pam_get_item(pamh, PAM_RHOST,(const void**)&buf);
        if (retval == PAM_SUCCESS && buf!=NULL) strncpy(clientId,buf,sizeof(clientId)-1);
	int idx=0;
	while(getItem(cfg.hosts,idx,host)>=0) {
		if(chkRadius(host, cfg.port,cfg.secret,cfg.nas, 2, 2, NULL)==PW_AUTHENTICATION_ACK) break;
		host[0]=0;idx++;
	}
	if(strlen(host)==0) return cfg.rBypass!=-1?cfg.rBypass:PAM_AUTH_ERR; 
        char reply[300];
        char state[300];
        char pass[100];
	reply[0]=0;
	state[0]=0;
	strncpy(pass,password,sizeof(pass)-1);
	idx=1;
	for(;;) {
        	retval=sendRequest(idx++, host, cfg.port, cfg.secret, cfg.nas, user, pass,clientId,cfg.timeout, cfg.retry, state, reply);
		if(retval!=PW_ACCESS_CHALLENGE) break;
		resp=NULL;
		int ret = pam_prompt(pamh,PAM_PROMPT_ECHO_ON,&resp,"%s: ",reply);
		if (ret != PAM_SUCCESS || resp==NULL ) return cfg.rInt!=-1?cfg.rInt:PAM_AUTHINFO_UNAVAIL;
                strncpy(pass,resp,sizeof(pass)-1);
		if(idx>255) idx=0;
        }
        if(retval==PW_AUTHENTICATION_ACK) return cfg.rOk!=-1?cfg.rOk:PAM_SUCCESS;
	return cfg.rFail!=-1?cfg.rFail:PAM_AUTH_ERR;
}
