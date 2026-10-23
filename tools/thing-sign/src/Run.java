import com.thingclips.smart.security.jni.SecureNativeApi;

public class Run {
    static {
        System.loadLibrary("c++_shared");
        System.loadLibrary("thing_security_algorithm");
        System.loadLibrary("thing_security");
        System.err.println("[run] libs loaded");
    }

    public static void main(String[] a) throws Exception {
        android.content.Context ctx = new android.content.Context();
        if (a.length > 0 && a[0].equals("digest")) {
            System.err.println("DIGEST=" + SecureNativeApi.computeDigest("abc", "key"));
            return;
        }
        if (a.length > 0 && a[0].equals("test")) {
            System.err.println("TESTSIGN=" + SecureNativeApi.testSign(ctx));
            return;
        }
        String canon = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/in.txt")), "UTF-8");
        String seed = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/seed.txt")), "UTF-8").trim();
        System.err.println("[run] init cmd0");
        Object r0 = SecureNativeApi.doCommandNative(ctx, 0, seed.getBytes("UTF-8"), "q95kcu85qnkdwaee9w3j".getBytes("UTF-8"), false);
        System.err.println("INIT=" + (r0 == null ? "null" : r0.toString()));
        System.err.println("[run] calling doCommandNative");
        Object r = SecureNativeApi.doCommandNative(new android.content.Context(), 1, canon.getBytes("UTF-8"), null, false);
        System.err.println("RESULT=" + (r == null ? "null" : r.toString()));
    }
}
