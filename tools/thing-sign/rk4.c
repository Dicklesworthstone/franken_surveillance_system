#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security_algorithm.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security_algorithm.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  FILE*b=fopen(argv[2],"rb"); fseek(b,0,SEEK_END); long m=ftell(b); fseek(b,0,SEEK_SET);
  unsigned char*bmp=malloc(m); fread(bmp,1,m,b); fclose(b);
  typedef int(*hf)(char*); int hv=((hf)(lo+0x51d0))(argv[1]);
  int plen=m-54; int idx=((hv%plen)/2)%plen;
  printf("hash=%d plen=%d idx=%d bytes=%d,%d,%d\n",hv,plen,idx,bmp[54+idx],bmp[54+idx+1],bmp[54+idx+2]);
  char**keys=NULL; int count=0;
  typedef int(*fn_t)(char*,char***,int*,char*);
  int r=((fn_t)(lo+0x4abc))(argv[1],&keys,&count,(char*)bmp);
  printf("r=%d count=%d\n",r,count);
  return 0;
}
