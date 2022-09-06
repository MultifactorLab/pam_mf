#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>

int getItem(char* items, int idx, char* res)
{
	int c=0;
        res[0]=0;
	for(c=0;c<strlen(items) && idx>0;c++)
		if(items[c]==',') idx--;
        if(idx>0) return -1;
	for(;c<strlen(items);c++) {
		if(items[c]==',') break;
		res[strlen(res)+1]=0;
		res[strlen(res)]=items[c];
	}
	return 0;
}
int findItem(char* item, char* items)
{
	int res=-1;
	char *str=malloc(strlen(items)+1);
	if(str==NULL) return -1;
	for(int c=0;getItem(items,c,str)>=0;c++)
		if(strcmp(str,item)==0) {
			res=c; break;
		}
	free(str);
	return res;		
}
int chkUser(char *user,char* groups) {

	char* str=NULL;
	struct passwd *pw;
        struct group *gr;
	int numGrp=0;
	char* chkGroups[100];
	pw = getpwnam(user);
	if(pw==NULL) return -1;
	if(!groups||strlen(groups)==0) return 0;
	gid_t *userGroups = malloc(sizeof(*userGroups) * 100);
	if(userGroups==NULL) return 0;
	for(;;) {      	
		str=malloc(100);
		if(str==NULL) break;
		if(getItem(groups,numGrp,str)<0) {
			free(str);
			break;
		}
		chkGroups[numGrp++]=str;	
	}
	if(numGrp==0) return 0;
        int n=100;
	int found=0;
        if (getgrouplist(user, pw->pw_gid, userGroups, &n) != -1) {
		for(int c=0;c<n;c++) {
			gr = getgrgid(userGroups[c]);
			if(gr!=NULL)
				for(int c1=0;c1<numGrp;c1++)
					if(strcmp(chkGroups[c1],gr->gr_name)==0) {
						found=1; break;
					} 	
		}		
	}
        for(int c=0;c<numGrp;c++) free(chkGroups[c]);
	free(userGroups);
	return found;	
}
