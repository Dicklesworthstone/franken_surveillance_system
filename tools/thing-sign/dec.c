#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security.so",RTLD_NOW|RTLD_GLOBAL);
  if(!h){puts(dlerror());return 1;}
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  unsigned char key[256],ct[256],iv[16],out[256];
  FILE*k=fopen(argv[1],"rb");int kn=fread(key,1,256,k);fclose(k);
  FILE*c=fopen(argv[2],"rb");int cn=fread(ct,1,256,c);fclose(c);
  memcpy(iv,"7178265647164836",16);
  typedef int(*fn_t)(unsigned char*,unsigned char*,int,unsigned char*,unsigned char*);
  fn_t fn=(fn_t)(lo+0x11098);
  memset(out,0,sizeof out);
  int r=fn(out,key,kn,ct,iv);
  printf("r=%d\n",r);
  for(int i=0;i<cn;i++){unsigned char ch=out[i];putchar(ch>=32&&ch<127?ch:'.');}
  printf("\nHEX:");for(int i=0;i<cn;i++)printf("%02x",out[i]);printf("\n");
  return 0;
}
