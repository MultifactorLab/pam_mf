#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <security/pam_modules.h>
#include "config.h"
#include "service.h"

void stripComment(char* str)
{
	for(int c=0;c<strlen(str);c++)
		if(str[c]=='#'||str[c]==';') {
			str[c]=0;
			break;
		} 	
}

void strToLower(char* str)
{
	for(int c=0;c<strlen(str);c++) 	
    		str[c]=tolower(str[c]);
}
void removeSpaces(char* str)
{
  char buf[300];
  strcpy(buf,str);
  str[0]=0;
  for(int c=0;c<strlen(buf);c++) 	
  	if(!isspace(buf[c])) {
		str[strlen(str)+1]=0;
		str[strlen(str)]=buf[c];
	}
}
int parseSting(char* buf, char* key, char* val)
{
	int c;
	int section=0;
	int phase=0;
	int value=0;
	key[0]=0;
	val[0]=0;
        char str[300];
      	if(!buf || strlen(buf)==0) return -1;
        strcpy(str,buf);
	for(c=strlen(str)-1;c>=0 && isspace(str[c]);c--) str[c]=0;
	if(strlen(str)==0) return -1;
        for(c=0;c<strlen(str);c++) {
		if(str[c]=='#'||str[c]==';') return -1;
		if(value) { 
			if(isspace(str[c])) {
				if(section) return -1;
				phase++;
				value=0;
				continue;
			}
			if(!section && phase==0 && str[c]=='=') {
				phase=2;
				value=0;
				continue;
			}
			if(phase==0 && section && str[c]==']') return 1;

			key[strlen(key)+1]=0;
			key[strlen(key)]=tolower(str[c]);
			continue;
	 	}
		else {
			if(isspace(str[c])) continue;
			if(phase==0 && str[c]=='[') {
				section=1;
				value=1;
				continue;
			}
			if(phase==1 && str[c]=='=') {
				phase=2;
				continue;
			}
			if(phase==2) {
				strcpy(val,str+c);
				stripComment(val);
				return 0;
			}
			value =1;c--;	
		}
	}
	return -1;
}
void mfLog(char *fileName, const char* p_format, ...)
{
	FILE *f=fopen(fileName,"a");
	if(f==NULL) return;
	va_list l_argp;
	
	va_start(l_argp, p_format);
	vfprintf(f,p_format, l_argp);
	va_end(l_argp);
	fclose(f);
	
}

void dumpConfig(char *fileName, mf_config_t* cfg)
{
	mfLog(fileName,"Hosts: %s\n",cfg->hosts);
	mfLog(fileName,"Port: %s\n",cfg->port);
	mfLog(fileName,"Secret: %s\n",cfg->secret);
	mfLog(fileName,"Nas: %s\n",cfg->nas);
	mfLog(fileName,"Users: %s\n",cfg->users);
	mfLog(fileName,"Groups: %s\n",cfg->groups);
	mfLog(fileName,"TimeOut: %d\n",cfg->timeout);
	mfLog(fileName,"Retry: %d\n",cfg->retry);
	mfLog(fileName,"Always: %d\n",cfg->rAlways);
	mfLog(fileName,"User: %d\n",cfg->rUser);
	mfLog(fileName,"Skip: %d\n",cfg->rSkip);
	mfLog(fileName,"Bypass: %d\n",cfg->rBypass);
	mfLog(fileName,"Inter: %d\n",cfg->rInt);
	mfLog(fileName,"ok: %d\n",cfg->rOk);
	mfLog(fileName,"Fail: %d\n",cfg->rFail);

}
void initConfig(mf_config_t* cfg)
{
	strcpy(cfg->hosts,"localhost");
	strcpy(cfg->port,"1812");
	strcpy(cfg->secret,"0000000000");
	strcpy(cfg->nas,"");
	strcpy(cfg->users,"");
	strcpy(cfg->groups,"");
	cfg->skipLocal=0;
        cfg->passRequired=0;
	cfg->timeout=20;
	cfg->retry=4;
        cfg->rAlways=-1;
	cfg->rUser=PAM_USER_UNKNOWN;
	cfg->rSkip=PAM_SUCCESS;
	cfg->rBypass=PAM_AUTH_ERR;
	cfg->rInt=PAM_AUTHINFO_UNAVAIL;
	cfg->rOk=PAM_SUCCESS;
	cfg->rFail=PAM_AUTH_ERR;
}

int isReturn(mf_config_t* cfg, char *key, char *val)
{
  int *p=NULL;
  if(strcmp(key,"always_return")==0) p=&(cfg->rAlways);
  if(strcmp(key,"unknown_user_result")==0) p=&(cfg->rUser);
  if(strcmp(key,"skip_result")==0) p=&(cfg->rSkip);
  if(strcmp(key,"bypass_result")==0) p=&(cfg->rBypass);
  if(strcmp(key,"interactive_unavailable_result")==0) p=&(cfg->rInt);
  if(strcmp(key,"access_accepted_result")==0) p=&(cfg->rOk);
  if(strcmp(key,"access_rejected_result")==0) p=&(cfg->rFail);
  if(!p) return -1;
  int ret=-100;
  strToLower(val);
  if(strcmp(val,"none")==0) ret=-1;
  else if(strcmp(val,"auth_err")==0) ret=PAM_AUTH_ERR;
  else if(strcmp(val,"cred_insufficient")==0) ret=PAM_CRED_INSUFFICIENT;
  else if(strcmp(val,"authinfo_unavail")==0) ret=PAM_AUTHINFO_UNAVAIL;
  else if(strcmp(val,"success")==0) ret=PAM_SUCCESS;
  else if(strcmp(val,"user_unknown")==0) ret=PAM_USER_UNKNOWN;
  if(ret!=-100) *p=ret;
  return 0;
}
int loadConfig(mf_config_t* cfg, char* file, char* service)
{
   	char section[300];
   	char cSection[300];
	cSection[0]=0;	
   	char key[300];	
   	char value[300];	
   	char str[300];	
   	int retValue=-1;
	if(service && strlen(service)>0) {
		strcpy(section,service);
		strToLower(section);
	}
	else strcpy(section,"general");
	FILE *f=fopen(file,"r");
	if(f==NULL) return retValue;	
	while (fgets(str, 300, f) != NULL) {
		int res=parseSting(str, key, value);
		if(res<0) continue;
		if(res==1) {
			strcpy(cSection,key);
			continue;
		}
		if(strcmp(section,cSection)!=0) continue;
		if(strcmp(key,"radius_hosts")==0) {
			strcpy(cfg->hosts,value);
			removeSpaces(cfg->hosts);
		}	
		if(strcmp(key,"skip_users")==0) {
			strcpy(cfg->users,value);
			removeSpaces(cfg->users);
		}
		if(findItem("local_users",cfg->users)>=0) cfg->skipLocal=1;
		if(strcmp(key,"skip_groups")==0) {
			strcpy(cfg->groups,value);
			removeSpaces(cfg->groups);
		}
		if(isReturn(cfg,key,value)==0) continue;	
		else if(strcmp(key,"radius_port")==0) strcpy(cfg->port,value);
		else if(strcmp(key,"password_required")==0) {
			strToLower(value);
			if(strcmp(value,"true")==0) cfg->passRequired=1;
			else cfg->passRequired=0;
		}
		else if(strcmp(key,"shared_secret")==0) strcpy(cfg->secret,value);
		else if(strcmp(key,"nas_indentifier")==0) strcpy(cfg->nas,value);
		else if(strcmp(key,"timeout")==0) cfg->timeout=atoi(value);
		else if(strcmp(key,"retransmit_count")==0) cfg->retry=atoi(value);
	}
	fclose(f);
	return retValue;	
}
