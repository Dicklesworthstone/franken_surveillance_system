#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security_algorithm.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security_algorithm.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  FILE*b=fopen(argv[1],"rb"); fseek(b,0,SEEK_END); long m=ftell(b); fseek(b,0,SEEK_SET);
  unsigned char*bmp=malloc(m); fread(bmp,1,m,b); fclose(b);
  typedef int(*fn_t)(void*,void*);
  int r=((fn_t)(lo+0x4b7c))(bmp,bmp+0xe);
  printf("parse r=%d\n",r);
  return 0;
}
