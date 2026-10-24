package com.thingclips.smart.security.jni;

public class JNICLibrary {
    public static android.content.Context ctx;
    public static void checkStatus(int i) {
        System.err.println("[jni] checkStatus " + i);
    }
    public static android.content.Context getContext() {
        return ctx;
    }
}
