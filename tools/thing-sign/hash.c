#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  unsigned char st[0x80]; unsigned char out[16];
  FILE*b=fopen(argv[1],"rb"); fseek(b,0,SEEK_END); long n=ftell(b); fseek(b,0,SEEK_SET);
  unsigned char*buf=malloc(n); fread(buf,1,n,b); fclose(b);
  ((void(*)(void*))(lo+0x17ed4))(st);
  ((void(*)(void*,void*,int))(lo+0x17ef0))(st,buf,(int)n);
  ((void(*)(void*,void*))(lo+0x18a5c))(st,out);
  for(int i=0;i<16;i++)printf("%02x",out[i]); printf("\n");
  return 0;
}
