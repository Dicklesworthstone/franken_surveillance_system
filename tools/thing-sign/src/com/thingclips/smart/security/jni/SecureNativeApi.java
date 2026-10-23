package com.thingclips.smart.security.jni;

import android.content.Context;

public class SecureNativeApi {
    public static native Object doCommandNative(Context c, int i, byte[] a, byte[] b, boolean z);
    public static native String computeDigest(String a, String b);
    public static native String decryptResponseData(String a, String b);
    public static native byte[] encryptPostData(String a, byte[] b);
    public static native String genKey(String a, String b, String c);
    public static native String getChKey(Context c, byte[] b);
    public static native String getConfig(Context c, String a, String b);
    public static native byte[] getEncryptoKey(String a, String b);
    public static native String testSign(Context c);
}
