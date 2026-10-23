#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>

char __sF[0x400];

typedef struct { FILE *f; long len; } AAsset;
static FILE *mgr_assets = NULL;

static char mgr_token;
void *AAssetManager_fromJava(void *env, void *mgr) { (void)env; (void)mgr; return &mgr_token; }
void *AAssetManager_open(void *m, const char *name, int mode) {
    (void)m; (void)mode;
    char p[512]; snprintf(p, sizeof p, "/w/assets/%s", name);
    FILE *f = fopen(p, "rb");
    if (!f) { fprintf(stderr, "[stub] asset miss %s\n", name); return NULL; }
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    AAsset *a = calloc(1, sizeof *a); a->f = f; a->len = l;
    fprintf(stderr, "[stub] asset open %s (%ld)\n", name, l);
    return a;
}
long AAsset_getLength(void *a) { return ((AAsset *)a)->len; }
int AAsset_read(void *a, void *buf, size_t n) { return (int)fread(buf, 1, n, ((AAsset *)a)->f); }
void AAsset_close(void *a) { AAsset *x = (AAsset *)a; if (x) { if (x->f) fclose(x->f); free(x); } }

int __vsprintf_chk(char *d, int f, size_t sl, const char *fmt, va_list ap) { (void)f; (void)sl; return vsprintf(d, fmt, ap); }
int __vsnprintf_chk(char *d, size_t n, int f, size_t sl, const char *fmt, va_list ap) { (void)f; (void)sl; return vsnprintf(d, n, fmt, ap); }
int __sprintf_chk(char *d, int f, size_t sl, const char *fmt, ...) { (void)f; (void)sl; va_list ap; va_start(ap, fmt); int r = vsprintf(d, fmt, ap); va_end(ap); return r; }
int __snprintf_chk(char *d, size_t n, int f, size_t sl, const char *fmt, ...) { (void)f; (void)sl; va_list ap; va_start(ap, fmt); int r = vsnprintf(d, n, fmt, ap); va_end(ap); return r; }
void __stack_chk_fail_local(void) {}
void android_set_abort_message(const char *m) { (void)m; }
void __assert2(const char *f, int l, const char *fn, const char *m) { fprintf(stderr, "%s:%d %s: %s\n", f, l, fn, m); }

size_t __strlen_chk(const char *s, size_t n) { size_t l = strlen(s); return (l >= n && n) ? n - 1 : l; }
void *__memcpy_chk(void *d, const void *s, size_t n, size_t dl) { (void)dl; return memcpy(d, s, n); }
void *__memmove_chk(void *d, const void *s, size_t n, size_t dl) { (void)dl; return memmove(d, s, n); }
void *__memset_chk(void *d, int c, size_t n, size_t dl) { (void)dl; return memset(d, c, n); }
char *__strcpy_chk(char *d, const char *s, size_t dl) { (void)dl; return strcpy(d, s); }
char *__strncpy_chk(char *d, const char *s, size_t n, size_t dl) { (void)dl; return strncpy(d, s, n); }
int __strcmp_chk(const char *a, const char *b) { return strcmp(a, b); }
char *__strchr_chk(const char *s, int c, size_t n) { (void)n; return strchr(s, c); }
char *__strrchr_chk(const char *s, int c, size_t n) { (void)n; return strrchr(s, c); }
char *__strcat_chk(char *d, const char *s, size_t dl) { (void)dl; return strcat(d, s); }
char *__strncat_chk(char *d, const char *s, size_t n, size_t dl) { (void)dl; return strncat(d, s, n); }

int __system_property_get(const char *name, char *value) { (void)name; if (value) value[0] = 0; return 0; }
int *__errno(void) { return __errno_location(); }
int __cxa_thread_atexit_impl(void (*fn)(void *), void *arg, void *dso) { (void)fn; (void)arg; (void)dso; return 0; }
long long strtoll_l(const char *s, char **e, int b, void *l) { (void)l; return strtoll(s, e, b); }
unsigned long long strtoull_l(const char *s, char **e, int b, void *l) { (void)l; return strtoull(s, e, b); }
