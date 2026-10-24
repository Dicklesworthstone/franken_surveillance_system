#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  unsigned char key[256],ct[256],iv[16]; unsigned char *p=NULL;
  FILE*k=fopen(argv[1],"rb");int kn=fread(key,1,256,k);fclose(k);
  FILE*c=fopen(argv[2],"rb");int cn=fread(ct,1,256,c);fclose(c);
  memcpy(iv,"7178265647164836",16);
  typedef int(*fn_t)(void*,unsigned char*,int,unsigned char*,unsigned char*);
  fn_t fn=(fn_t)(lo+0x11098);
  int r=fn(&p,key,kn,ct,iv);
  printf("r=%d p=%p\n",r,(void*)p);
  if(p){for(int i=0;i<cn;i++){unsigned char ch=p[i];putchar(ch>=32&&ch<127?ch:'.');}printf("\n");}
  return 0;
}
