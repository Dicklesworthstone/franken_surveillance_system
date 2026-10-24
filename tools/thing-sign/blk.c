#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(){
  void*h=dlopen("/w/libs/libthing_security.so",RTLD_NOW|RTLD_GLOBAL);
  FILE*f=fopen("/proc/self/maps","r");char l[512];unsigned long lo=0;
  while(fgets(l,sizeof l,f)){unsigned long a,b;if(strstr(l,"libthing_security.so")&&sscanf(l,"%lx-%lx",&a,&b)==2){lo=a;break;}}
  fclose(f);
  unsigned char key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  unsigned char st[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  *(unsigned long*)(lo+0x383e8)=(unsigned long)key;
  *(unsigned long*)(lo+0x383e0)=(unsigned long)st;
  typedef void(*fn_t)(void);
  ((fn_t)(lo+0x11424))();
  ((fn_t)(lo+0x114fc))();
  for(int i=0;i<16;i++)printf("%02x",st[i]);
  printf("\n");
  return 0;
}
