#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *CNONCE = "EE5CA138D413A3D6";
static const char *NONCE  = "C87CEA0BF708DC5D";
static const char *CONFIRM= "9E564565B131F3821B8ADB885EA691FB";
static char *buf; static size_t bufsz; static int found;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void hexup(const unsigned char *in, size_t n, char *out) {
    static const char *H = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[in[i] >> 4]; out[2*i+1] = H[in[i] & 15]; }
    out[2*n] = 0;
}

static int try_pw(const char *pw) {
    unsigned char h1[32], h2[32];
    char p1[65], msg[256], p2[65], calc[200];
    SHA256((const unsigned char *)pw, strlen(pw), h1);
    hexup(h1, 32, p1);
    snprintf(msg, sizeof msg, "%s%s%s", CNONCE, p1, NONCE);
    SHA256((const unsigned char *)msg, strlen(msg), h2);
    hexup(h2, 32, p2);
    snprintf(calc, sizeof calc, "%s%s%s", p2, NONCE, CNONCE);
    return strcasecmp(calc, CONFIRM) == 0;
}

typedef struct { char *start; size_t len; } slice_t;

static void *worker(void *arg) {
    slice_t *s = arg;
    char *p = s->start, *end = s->start + s->len;
    while (p < end && !found) {
        char *nl = memchr(p, '\n', end - p);
        size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (n && (p[n-1] == '\r')) n--;
        if (n) {
            char tmp[128]; size_t k = n < sizeof tmp - 1 ? n : sizeof tmp - 1;
            memcpy(tmp, p, k); tmp[k] = 0;
            if (try_pw(tmp)) { pthread_mutex_lock(&mtx); if (!found) { found = 1; printf("MATCH %s\n", tmp); fflush(stdout);} pthread_mutex_unlock(&mtx); }
        }
        p = nl ? nl + 1 : end;
    }
    return NULL;
}

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); bufsz = ftell(f); fseek(f, 0, SEEK_SET);
    buf = malloc(bufsz + 1); fread(buf, 1, bufsz, f); fclose(f);
    int nt = argc > 2 ? atoi(argv[2]) : 8;
    pthread_t th[64]; slice_t sl[64]; size_t chunk = bufsz / nt;
    for (int i = 0; i < nt; i++) { sl[i].start = buf + i*chunk; sl[i].len = (i == nt-1) ? bufsz - i*chunk : chunk; pthread_create(&th[i], 0, worker, &sl[i]); }
    for (int i = 0; i < nt; i++) pthread_join(th[i], 0);
    if (!found) printf("NO MATCH\n");
    return found ? 0 : 1;
}
