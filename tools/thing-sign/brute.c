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
  char*bmp=malloc(m); fread(bmp,1,m,b); fclose(b);
  char*base=argv[2];
  char buf[4096];
  for(int n=0;n<200000;n++){
    // insert "||nonce=%08x" before "||os="
    char*t=strstr(base,"||os=");
    int pre=t-base;
    snprintf(buf,sizeof buf,"%.*s||nonce=%08x%s",pre,base,n,t);
    char**keys=NULL; int count=0;
    typedef int(*fn_t)(char*,char***,int*,char*);
    int r=((fn_t)(lo+0x4abc))(buf,&keys,&count,(char*)bmp);
    if(r==0){printf("nonce=%d count=%d\n%s\n",n,count,buf);for(int j=0;j<count;j++)printf("K%d=%s\n",j,keys[j]);return 0;}
  }
  puts("none"); return 1;
}
