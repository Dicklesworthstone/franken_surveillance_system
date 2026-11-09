#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "C460_GPL/sdk/soc/ssc30x/boot/u-boot/lib/lzma/LzmaDec.h"
static void *SzAlloc(void *p, size_t s){ (void)p; return malloc(s); }
static void SzFree(void *p, void *a){ (void)p; free(a); }
static ISzAlloc g = { SzAlloc, SzFree };
int main(int argc, char **argv){
  if (argc < 4) { fprintf(stderr, "usage: lzd <file> <off> <dict> [lc lp pb]\n"); return 2; }
  FILE *f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  unsigned char *buf = malloc(n); fread(buf, 1, n, f); fclose(f);
  long off = strtol(argv[2], 0, 0);
  size_t cap = 8<<20; unsigned char *out = malloc(cap); size_t outLen = cap, srcLen = n - off;
  unsigned char props[5]; props[0] = (unsigned char)(strtol(argv[4]?argv[4]:"0",0,0) + 9*strtol(argv[5]?argv[5]:"0",0,0) + 45*strtol(argv[6]?argv[6]:"0",0,0));
  unsigned long dict = strtoul(argv[3], 0, 0);
  props[1]=dict&0xff; props[2]=(dict>>8)&0xff; props[3]=(dict>>16)&0xff; props[4]=(dict>>24)&0xff;
  ELzmaStatus st; SRes r = LzmaDecode(out, &outLen, buf+off, &srcLen, props, 5, LZMA_FINISH_END, &st, &g);
  fprintf(stderr, "res=%d status=%d outLen=%zu\n", r, st, outLen);
  fwrite(out, 1, outLen, stdout);
  return r;
}
