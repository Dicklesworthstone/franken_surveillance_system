#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "traps.h"
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
static void onsegv(int sig, siginfo_t *si, void *uc) {
    (void)sig; ucontext_t *u = (ucontext_t *)uc;
    fprintf(stderr, "SEGV at pc=%p addr=%p\n", (void*)u->uc_mcontext.pc, si->si_addr);
    _exit(139);
}

typedef struct { jsize len; unsigned char *data; } FakeArr;

static jsize JNICALL f_GetArrayLength(JNIEnv *e, jarray a) { (void)e; fprintf(stderr, "[JNI] GetArrayLength\n"); return ((FakeArr *)a)->len; }
static jbyte *JNICALL f_GetByteArrayElements(JNIEnv *e, jbyteArray a, jboolean *c) { (void)e; fprintf(stderr, "[JNI] GetByteArrayElements\n"); if (c) *c = 0; return ((FakeArr *)a)->data; }
static void JNICALL f_ReleaseByteArrayElements(JNIEnv *e, jbyteArray a, jbyte *p, jint m) { (void)e; (void)a; (void)p; (void)m; }
static jstring JNICALL f_NewStringUTF(JNIEnv *e, const char *s) { (void)e; fprintf(stderr, "[JNI] NewStringUTF(%s)\n", s); return (jstring)strdup(s); }
static const char *JNICALL f_GetStringUTFChars(JNIEnv *e, jstring s, jboolean *c) { (void)e; if (c) *c = 0; return (const char *)s; }
static void JNICALL f_ReleaseStringUTFChars(JNIEnv *e, jstring s, const char *c) { (void)e; (void)s; (void)c; }
static jint JNICALL f_RegNatives(JNIEnv *e, jclass c, const JNINativeMethod *m, jint n) { (void)e; (void)c; (void)m; fprintf(stderr, "[JNI] RegisterNatives n=%d\n", n); return 0; }
static jint JNICALL f_ThrowNew(JNIEnv *e, jclass c, const char *m) { (void)e; (void)c; fprintf(stderr, "JNI EXC: %s\n", m); return 0; }
static int find_n;
static jclass JNICALL f_FindClass(JNIEnv *e, const char *n) { (void)e; find_n++; if (find_n == 1) { fprintf(stderr, "[JNI] FindClass#1 -> 0\n"); return 0; } fprintf(stderr, "[JNI] FindClass#%d ptr=%p\n", find_n, (void*)n); if (n) fprintf(stderr, "      name=%s\n", n); return (jclass)1; }
static void JNICALL f_ExceptionDescribe(JNIEnv *e) { (void)e; }
static void JNICALL f_SetByteArrayRegion(JNIEnv *e, jbyteArray a, jsize s, jsize l, const jbyte *b) {
    (void)e; FakeArr *f = (FakeArr *)a; if (s + l <= f->len) memcpy(f->data + s, b, l);
}


static jclass JNICALL f_GetObjectClass(JNIEnv *e, jobject o) { (void)e; (void)o; fprintf(stderr, "[JNI] GetObjectClass\n"); return (jclass)1; }
static jmethodID JNICALL f_GetMethodID(JNIEnv *e, jclass c, const char *n, const char *sig) { (void)e; (void)c; fprintf(stderr, "[JNI] GetMethodID %s\n", n); if (!strcmp(n,"getAssets")) return (jmethodID)10; if (!strcmp(n,"getPackageManager")) return (jmethodID)11; if (!strcmp(n,"getPackageName")) return (jmethodID)12; return (jmethodID)2; }
static jmethodID JNICALL f_GetStaticMethodID(JNIEnv *e, jclass c, const char *n, const char *sig) { (void)e; (void)c; fprintf(stderr, "[JNI] GetStaticMethodID %s %s\n", n, sig); return (jmethodID)3; }
static jfieldID JNICALL f_GetFieldID(JNIEnv *e, jclass c, const char *n, const char *sig) { (void)e; (void)c; fprintf(stderr, "[JNI] GetFieldID %s %s\n", n, sig); return (jfieldID)5; }
static jobject JNICALL f_CallObjectMethodV(JNIEnv *e, jobject o, jmethodID m, va_list a) { (void)e; (void)o; (void)a; long k=(long)m; fprintf(stderr, "[JNI] CallObjectMethodV %ld\n", k); if (k==12) return (jobject)strdup("com.glazero.android"); return (jobject)(void*)(0x1000+k); }
static jobject JNICALL f_CallStaticObjectMethodV(JNIEnv *e, jclass c, jmethodID m, va_list a) { (void)e; (void)c; (void)m; (void)a; fprintf(stderr, "[JNI] CallStaticObjectMethodV\n"); return (jobject)4; }
static jobject JNICALL f_GetObjectField(JNIEnv *e, jobject o, jfieldID f) { (void)e; (void)o; (void)f; fprintf(stderr, "[JNI] GetObjectField\n"); return (jobject)4; }
static jobject JNICALL f_NewGlobalRef(JNIEnv *e, jobject o) { (void)e; return o; }
static jboolean JNICALL f_ExceptionCheck(JNIEnv *e) { (void)e; return 0; }
static jthrowable JNICALL f_ExceptionOccurred(JNIEnv *e) { (void)e; return 0; }

int main(int argc, char **argv) {
    struct JNINativeInterface_ env;
    memset(&env, 0, sizeof env);
    ((void **)&env)[0] = (void *)t0;
    ((void **)&env)[1] = (void *)t1;
    ((void **)&env)[2] = (void *)t2;
    ((void **)&env)[3] = (void *)t3;
    ((void **)&env)[4] = (void *)t4;
    ((void **)&env)[5] = (void *)t5;
    ((void **)&env)[6] = (void *)t6;
    ((void **)&env)[7] = (void *)t7;
    ((void **)&env)[8] = (void *)t8;
    ((void **)&env)[9] = (void *)t9;
    ((void **)&env)[10] = (void *)t10;
    ((void **)&env)[11] = (void *)t11;
    ((void **)&env)[12] = (void *)t12;
    ((void **)&env)[13] = (void *)t13;
    ((void **)&env)[14] = (void *)t14;
    ((void **)&env)[15] = (void *)t15;
    ((void **)&env)[16] = (void *)t16;
    ((void **)&env)[17] = (void *)t17;
    ((void **)&env)[18] = (void *)t18;
    ((void **)&env)[19] = (void *)t19;
    ((void **)&env)[20] = (void *)t20;
    ((void **)&env)[21] = (void *)t21;
    ((void **)&env)[22] = (void *)t22;
    ((void **)&env)[23] = (void *)t23;
    ((void **)&env)[24] = (void *)t24;
    ((void **)&env)[25] = (void *)t25;
    ((void **)&env)[26] = (void *)t26;
    ((void **)&env)[27] = (void *)t27;
    ((void **)&env)[28] = (void *)t28;
    ((void **)&env)[29] = (void *)t29;
    ((void **)&env)[30] = (void *)t30;
    ((void **)&env)[31] = (void *)t31;
    ((void **)&env)[32] = (void *)t32;
    ((void **)&env)[33] = (void *)t33;
    ((void **)&env)[34] = (void *)t34;
    ((void **)&env)[35] = (void *)t35;
    ((void **)&env)[36] = (void *)t36;
    ((void **)&env)[37] = (void *)t37;
    ((void **)&env)[38] = (void *)t38;
    ((void **)&env)[39] = (void *)t39;
    ((void **)&env)[40] = (void *)t40;
    ((void **)&env)[41] = (void *)t41;
    ((void **)&env)[42] = (void *)t42;
    ((void **)&env)[43] = (void *)t43;
    ((void **)&env)[44] = (void *)t44;
    ((void **)&env)[45] = (void *)t45;
    ((void **)&env)[46] = (void *)t46;
    ((void **)&env)[47] = (void *)t47;
    ((void **)&env)[48] = (void *)t48;
    ((void **)&env)[49] = (void *)t49;
    ((void **)&env)[50] = (void *)t50;
    ((void **)&env)[51] = (void *)t51;
    ((void **)&env)[52] = (void *)t52;
    ((void **)&env)[53] = (void *)t53;
    ((void **)&env)[54] = (void *)t54;
    ((void **)&env)[55] = (void *)t55;
    ((void **)&env)[56] = (void *)t56;
    ((void **)&env)[57] = (void *)t57;
    ((void **)&env)[58] = (void *)t58;
    ((void **)&env)[59] = (void *)t59;
    ((void **)&env)[60] = (void *)t60;
    ((void **)&env)[61] = (void *)t61;
    ((void **)&env)[62] = (void *)t62;
    ((void **)&env)[63] = (void *)t63;
    ((void **)&env)[64] = (void *)t64;
    ((void **)&env)[65] = (void *)t65;
    ((void **)&env)[66] = (void *)t66;
    ((void **)&env)[67] = (void *)t67;
    ((void **)&env)[68] = (void *)t68;
    ((void **)&env)[69] = (void *)t69;
    ((void **)&env)[70] = (void *)t70;
    ((void **)&env)[71] = (void *)t71;
    ((void **)&env)[72] = (void *)t72;
    ((void **)&env)[73] = (void *)t73;
    ((void **)&env)[74] = (void *)t74;
    ((void **)&env)[75] = (void *)t75;
    ((void **)&env)[76] = (void *)t76;
    ((void **)&env)[77] = (void *)t77;
    ((void **)&env)[78] = (void *)t78;
    ((void **)&env)[79] = (void *)t79;
    ((void **)&env)[80] = (void *)t80;
    ((void **)&env)[81] = (void *)t81;
    ((void **)&env)[82] = (void *)t82;
    ((void **)&env)[83] = (void *)t83;
    ((void **)&env)[84] = (void *)t84;
    ((void **)&env)[85] = (void *)t85;
    ((void **)&env)[86] = (void *)t86;
    ((void **)&env)[87] = (void *)t87;
    ((void **)&env)[88] = (void *)t88;
    ((void **)&env)[89] = (void *)t89;
    ((void **)&env)[90] = (void *)t90;
    ((void **)&env)[91] = (void *)t91;
    ((void **)&env)[92] = (void *)t92;
    ((void **)&env)[93] = (void *)t93;
    ((void **)&env)[94] = (void *)t94;
    ((void **)&env)[95] = (void *)t95;
    ((void **)&env)[96] = (void *)t96;
    ((void **)&env)[97] = (void *)t97;
    ((void **)&env)[98] = (void *)t98;
    ((void **)&env)[99] = (void *)t99;
    ((void **)&env)[100] = (void *)t100;
    ((void **)&env)[101] = (void *)t101;
    ((void **)&env)[102] = (void *)t102;
    ((void **)&env)[103] = (void *)t103;
    ((void **)&env)[104] = (void *)t104;
    ((void **)&env)[105] = (void *)t105;
    ((void **)&env)[106] = (void *)t106;
    ((void **)&env)[107] = (void *)t107;
    ((void **)&env)[108] = (void *)t108;
    ((void **)&env)[109] = (void *)t109;
    ((void **)&env)[110] = (void *)t110;
    ((void **)&env)[111] = (void *)t111;
    ((void **)&env)[112] = (void *)t112;
    ((void **)&env)[113] = (void *)t113;
    ((void **)&env)[114] = (void *)t114;
    ((void **)&env)[115] = (void *)t115;
    ((void **)&env)[116] = (void *)t116;
    ((void **)&env)[117] = (void *)t117;
    ((void **)&env)[118] = (void *)t118;
    ((void **)&env)[119] = (void *)t119;
    ((void **)&env)[120] = (void *)t120;
    ((void **)&env)[121] = (void *)t121;
    ((void **)&env)[122] = (void *)t122;
    ((void **)&env)[123] = (void *)t123;
    ((void **)&env)[124] = (void *)t124;
    ((void **)&env)[125] = (void *)t125;
    ((void **)&env)[126] = (void *)t126;
    ((void **)&env)[127] = (void *)t127;
    ((void **)&env)[128] = (void *)t128;
    ((void **)&env)[129] = (void *)t129;
    ((void **)&env)[130] = (void *)t130;
    ((void **)&env)[131] = (void *)t131;
    ((void **)&env)[132] = (void *)t132;
    ((void **)&env)[133] = (void *)t133;
    ((void **)&env)[134] = (void *)t134;
    ((void **)&env)[135] = (void *)t135;
    ((void **)&env)[136] = (void *)t136;
    ((void **)&env)[137] = (void *)t137;
    ((void **)&env)[138] = (void *)t138;
    ((void **)&env)[139] = (void *)t139;
    ((void **)&env)[140] = (void *)t140;
    ((void **)&env)[141] = (void *)t141;
    ((void **)&env)[142] = (void *)t142;
    ((void **)&env)[143] = (void *)t143;
    ((void **)&env)[144] = (void *)t144;
    ((void **)&env)[145] = (void *)t145;
    ((void **)&env)[146] = (void *)t146;
    ((void **)&env)[147] = (void *)t147;
    ((void **)&env)[148] = (void *)t148;
    ((void **)&env)[149] = (void *)t149;
    ((void **)&env)[150] = (void *)t150;
    ((void **)&env)[151] = (void *)t151;
    ((void **)&env)[152] = (void *)t152;
    ((void **)&env)[153] = (void *)t153;
    ((void **)&env)[154] = (void *)t154;
    ((void **)&env)[155] = (void *)t155;
    ((void **)&env)[156] = (void *)t156;
    ((void **)&env)[157] = (void *)t157;
    ((void **)&env)[158] = (void *)t158;
    ((void **)&env)[159] = (void *)t159;
    ((void **)&env)[160] = (void *)t160;
    ((void **)&env)[161] = (void *)t161;
    ((void **)&env)[162] = (void *)t162;
    ((void **)&env)[163] = (void *)t163;
    ((void **)&env)[164] = (void *)t164;
    ((void **)&env)[165] = (void *)t165;
    ((void **)&env)[166] = (void *)t166;
    ((void **)&env)[167] = (void *)t167;
    ((void **)&env)[168] = (void *)t168;
    ((void **)&env)[169] = (void *)t169;
    ((void **)&env)[170] = (void *)t170;
    ((void **)&env)[171] = (void *)t171;
    ((void **)&env)[172] = (void *)t172;
    ((void **)&env)[173] = (void *)t173;
    ((void **)&env)[174] = (void *)t174;
    ((void **)&env)[175] = (void *)t175;
    ((void **)&env)[176] = (void *)t176;
    ((void **)&env)[177] = (void *)t177;
    ((void **)&env)[178] = (void *)t178;
    ((void **)&env)[179] = (void *)t179;
    ((void **)&env)[180] = (void *)t180;
    ((void **)&env)[181] = (void *)t181;
    ((void **)&env)[182] = (void *)t182;
    ((void **)&env)[183] = (void *)t183;
    ((void **)&env)[184] = (void *)t184;
    ((void **)&env)[185] = (void *)t185;
    ((void **)&env)[186] = (void *)t186;
    ((void **)&env)[187] = (void *)t187;
    ((void **)&env)[188] = (void *)t188;
    ((void **)&env)[189] = (void *)t189;
    ((void **)&env)[190] = (void *)t190;
    ((void **)&env)[191] = (void *)t191;
    ((void **)&env)[192] = (void *)t192;
    ((void **)&env)[193] = (void *)t193;
    ((void **)&env)[194] = (void *)t194;
    ((void **)&env)[195] = (void *)t195;
    ((void **)&env)[196] = (void *)t196;
    ((void **)&env)[197] = (void *)t197;
    ((void **)&env)[198] = (void *)t198;
    ((void **)&env)[199] = (void *)t199;
    ((void **)&env)[200] = (void *)t200;
    ((void **)&env)[201] = (void *)t201;
    ((void **)&env)[202] = (void *)t202;
    ((void **)&env)[203] = (void *)t203;
    ((void **)&env)[204] = (void *)t204;
    ((void **)&env)[205] = (void *)t205;
    ((void **)&env)[206] = (void *)t206;
    ((void **)&env)[207] = (void *)t207;
    ((void **)&env)[208] = (void *)t208;
    ((void **)&env)[209] = (void *)t209;
    ((void **)&env)[210] = (void *)t210;
    ((void **)&env)[211] = (void *)t211;
    ((void **)&env)[212] = (void *)t212;
    ((void **)&env)[213] = (void *)t213;
    ((void **)&env)[214] = (void *)t214;
    ((void **)&env)[215] = (void *)t215;
    ((void **)&env)[216] = (void *)t216;
    ((void **)&env)[217] = (void *)t217;
    ((void **)&env)[218] = (void *)t218;
    ((void **)&env)[219] = (void *)t219;
    ((void **)&env)[220] = (void *)t220;
    ((void **)&env)[221] = (void *)t221;
    ((void **)&env)[222] = (void *)t222;
    ((void **)&env)[223] = (void *)t223;
    ((void **)&env)[224] = (void *)t224;
    ((void **)&env)[225] = (void *)t225;
    ((void **)&env)[226] = (void *)t226;
    ((void **)&env)[227] = (void *)t227;
    ((void **)&env)[228] = (void *)t228;
    ((void **)&env)[229] = (void *)t229;
    ((void **)&env)[230] = (void *)t230;
    ((void **)&env)[231] = (void *)t231;
    ((void **)&env)[232] = (void *)t232;
    ((void **)&env)[233] = (void *)t233;
    ((void **)&env)[234] = (void *)t234;
    ((void **)&env)[235] = (void *)t235;
    ((void **)&env)[236] = (void *)t236;
    ((void **)&env)[237] = (void *)t237;
    ((void **)&env)[238] = (void *)t238;
    ((void **)&env)[239] = (void *)t239;
    ((void **)&env)[240] = (void *)t240;
    ((void **)&env)[241] = (void *)t241;
    ((void **)&env)[242] = (void *)t242;
    ((void **)&env)[243] = (void *)t243;
    ((void **)&env)[244] = (void *)t244;
    ((void **)&env)[245] = (void *)t245;
    ((void **)&env)[246] = (void *)t246;
    ((void **)&env)[247] = (void *)t247;
    ((void **)&env)[248] = (void *)t248;
    ((void **)&env)[249] = (void *)t249;
    env.GetArrayLength = f_GetArrayLength;
    env.GetByteArrayElements = f_GetByteArrayElements;
    env.ReleaseByteArrayElements = f_ReleaseByteArrayElements;
    env.NewStringUTF = f_NewStringUTF;
    env.GetStringUTFChars = f_GetStringUTFChars;
    env.ReleaseStringUTFChars = f_ReleaseStringUTFChars;
    env.ThrowNew = f_ThrowNew;
    env.FindClass = f_FindClass;
    env.ExceptionDescribe = f_ExceptionDescribe;
    env.SetByteArrayRegion = f_SetByteArrayRegion;
    env.GetObjectClass = f_GetObjectClass;
    env.GetMethodID = f_GetMethodID;
    env.GetStaticMethodID = f_GetStaticMethodID;
    env.GetFieldID = f_GetFieldID;
    env.CallObjectMethodV = f_CallObjectMethodV;
    env.CallStaticObjectMethodV = f_CallStaticObjectMethodV;
    env.GetObjectField = f_GetObjectField;
    env.NewGlobalRef = f_NewGlobalRef;
    env.ExceptionCheck = f_ExceptionCheck;
    env.ExceptionOccurred = f_ExceptionOccurred;
    env.RegisterNatives = f_RegNatives;

    void *h = dlopen("/w/libs/libthing_security.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned char *base = (unsigned char *)h;
    /* the handle is not the base; resolve via dlinfo-free trick: use the first mapping */
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512]; unsigned long lo = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long a, b;
        if (strstr(line, "libthing_security.so") && sscanf(line, "%lx-%lx", &a, &b) == 2) { lo = a; break; }
    }
    fclose(f);
    if (!lo) { fprintf(stderr, "no base\n"); return 1; }
    struct JNINativeInterface_ *vt = &env;
    typedef jint (*onload_t)(JNIEnv *, void *);
    onload_t onl = (onload_t)(lo + 0x13790);
    jint jv = onl((JNIEnv *)&vt, NULL);
    fprintf(stderr, "[harness] JNI_OnLoad -> 0x%x\n", jv);
    typedef void *(*fn_t)(JNIEnv *, jclass, jobject, jint, jbyteArray, jbyteArray, jboolean);
    fn_t fn = (fn_t)(lo + 0x13848);

    FILE *in = fopen(argv[1], "rb");
    unsigned char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, in); buf[n] = 0; fclose(in);
    FakeArr arr = { (jsize)n, buf };
    fprintf(stderr, "input %zu bytes\n", n);
    struct JNINativeInterface_ *tbl = &env;
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = onsegv; sa.sa_flags = SA_SIGINFO; sigaction(SIGSEGV, &sa, 0); sigaction(SIGBUS, &sa, 0);
    fprintf(stderr, "[harness] calling fn at %p\n", (void*)fn);
    if (argc > 2) {
        for (int i = 2; i < argc; i++) {
            FILE *cf = fopen(argv[i], "rb");
            unsigned char cb[4096]; size_t cn = fread(cb, 1, sizeof cb - 1, cf); cb[cn] = 0; fclose(cf);
            FakeArr ca = { (jsize)cn, cb };
            void *r0 = fn((JNIEnv *)&tbl, (jclass)1, (jobject)0x1000, 0, (jbyteArray)&ca, (jbyteArray)&arr, JNI_FALSE);
            fprintf(stderr, "INIT(%s)=%s\n", argv[i], r0 ? (char *)r0 : "null");
        }
    }
    void *r = fn((JNIEnv *)&tbl, (jclass)1, (jobject)0x1000, 1, (jbyteArray)&arr, NULL, JNI_FALSE);
    fprintf(stderr, "RESULT=%s\n", r ? (char *)r : "null");
    return 0;
}
