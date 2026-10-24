#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
int main(int argc,char**argv){
  void*h=dlopen("/w/libs/libthing_security_algorithm.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security_algorithm.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  typedef int(*fn_t)(char*);
  int v=((fn_t)(lo+0x51d0))(argv[1]);
  printf("%d\n",v);
  return 0;
}
