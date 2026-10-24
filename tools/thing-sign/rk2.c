#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security_algorithm.so",RTLD_NOW|RTLD_GLOBAL);
  if(!h){puts(dlerror());return 1;}
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security_algorithm.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  FILE*i=fopen(argv[1],"rb"); fseek(i,0,SEEK_END); long n=ftell(i); fseek(i,0,SEEK_SET);
  char*in=malloc(n+1); fread(in,1,n,i); in[n]=0; fclose(i);
  FILE*b=fopen(argv[2],"rb"); fseek(b,0,SEEK_END); long m=ftell(b); fseek(b,0,SEEK_SET);
  unsigned char*bmp=malloc(m); fread(bmp,1,m,b); fclose(b);
  printf("magic %c%c size %u off %u depth %u comp %u len %ld\n",bmp[0],bmp[1],*(unsigned*)(bmp+2),*(unsigned*)(bmp+0xa),*(unsigned short*)(bmp+0x1c),*(unsigned*)(bmp+0x1e),m);
  char**keys=NULL; int count=0;
  typedef int(*fn_t)(char*,char***,int*,char*);
  int r=((fn_t)(lo+0x4abc))(in,&keys,&count,(char*)bmp);
  printf("r=%d count=%d\n",r,count);
  return 0;
}
