#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "lz19/C/Lzma2Dec.h"
#include "lz19/C/LzmaDec.h"
static void *A(const ISzAlloc *p, size_t s){(void)p;return malloc(s);}
static void F(const ISzAlloc *p, void *a){(void)p;free(a);}
static ISzAlloc g={A,F};
int main(int argc,char**argv){
  if(argc<4){fprintf(stderr,"usage: l2d3 <file> <off> <dictprop>\n");return 2;}
  FILE*f=fopen(argv[1],"rb");fseek(f,0,SEEK_END);long n=ftell(f);fseek(f,0,SEEK_SET);
  unsigned char*b=malloc(n); if(fread(b,1,n,f)!=(size_t)n) return 2; fclose(f);
  long off=strtol(argv[2],0,0); int dp=atoi(argv[3]); extern unsigned g_unpack; int props=-1; if(argc>4) props=atoi(argv[4]);
  if(argc>6) g_unpack = strtoul(argv[6],0,0);
  size_t maxout = argc>5? strtoul(argv[5],0,0):0; size_t cap=0xFFFFFFFFull;
  unsigned char*o=mmap(0,cap,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0); if(o==MAP_FAILED){fprintf(stderr,"mmap\n");return 3;}
  CLzma2Dec d; memset(&d,0,sizeof d); Lzma2Dec_Construct(&d);
  if(Lzma2Dec_Allocate(&d,(Byte)dp,&g)!=SZ_OK){fprintf(stderr,"alloc\n");return 3;}
  if(props>=0) d.decoder.prop.lc=0, d.decoder.prop.lp=0, d.decoder.prop.pb=0; d.decoder.dic=o; d.decoder.dicBufSize=cap; d.decoder.prop.dicSize=cap; Lzma2Dec_Init(&d);
  size_t total=(size_t)(n-off), done=0;
  ELzmaStatus st;
  int SKIP = getenv("SKIP") ? atoi(getenv("SKIP")) : 0;
  for(int i=0;i<400000 && done<total;i++){
    if(maxout && d.decoder.dicPos>=maxout) break;
    size_t sl=total-done;
    SRes r=Lzma2Dec_DecodeToDic(&d, cap, b+off+done, &sl, LZMA_FINISH_ANY, &st);
    done+=sl;
    fprintf(stderr,"it=%d done=%zu dicPos=%u st=%d\n", i, done, (unsigned)d.decoder.dicPos, (int)st);
    /* shim removed: LzmaDecU already returns OK for a pending match */
    if(r!=SZ_OK && d.decoder.remainLen==0) { fprintf(stderr,"res=%d st=%d out=%u src=%zu\n",(int)r,(int)st,(unsigned)d.decoder.dicPos, done); break; }
    if(d.state==8) { if(done<total && b[off+done]==0) done++; d.decoder.remainLen = 276; d.state = 0; d.needInitLevel = 0; continue; }   /* 0x00 ends a stream; the next byte is another control */
    if(!sl && d.decoder.remainLen==0) { if(SKIP) { done += SKIP; continue; } break; }
  }
  if(maxout && d.decoder.dicPos>maxout) d.decoder.dicPos=(SizeT)maxout;
  fwrite(o,1,d.decoder.dicPos,stdout);
  return 0;
}
