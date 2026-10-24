#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(){
  void*h=dlopen("/w/libs/libthing_security.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  unsigned char key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  *(unsigned long*)(lo+0x383e8)= (unsigned long)key;
  typedef void(*fn_t)(void);
  ((fn_t)(lo+0x11424))();
  unsigned char*rk=(unsigned char*)(lo+0x383f0);
  for(int i=0;i<176;i++)printf("%02x",rk[i]);
  printf("\n");
  return 0;
}
