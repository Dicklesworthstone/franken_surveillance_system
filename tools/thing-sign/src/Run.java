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
        if (a.length > 0 && a[0].equals("enc")) {
            String sd = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/seed.txt")),"UTF-8").trim();
            String ai = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/appid.txt")),"UTF-8").trim();
            SecureNativeApi.doCommandNative(ctx, 0, sd.getBytes(), ai.getBytes(), false);
            SecureNativeApi.doCommandNative(ctx, 1, "warmup".getBytes(), null, false);
            byte[] k = SecureNativeApi.getEncryptoKey(a[1], a.length > 2 ? a[2] : null);
            StringBuilder sb = new StringBuilder();
            if (k != null) for (byte b : k) sb.append(String.format("%02x", b));
            System.err.println("KEY=" + sb);
            return;
        }
        if (a.length > 0 && a[0].equals("chkey")) {
            String sd = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/seed.txt")),"UTF-8").trim();
            String ai2 = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/appid.txt")),"UTF-8").trim();
            SecureNativeApi.doCommandNative(ctx, 0, sd.getBytes(), ai2.getBytes(), false);
            SecureNativeApi.doCommandNative(ctx, 1, "warmup".getBytes(), null, false);
            String k = SecureNativeApi.getChKey(new android.content.Context(), new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/appid.txt")),"UTF-8").trim().getBytes());
            System.err.println("CHKEY=" + k);
            return;
        }
        if (a.length > 0 && a[0].equals("test")) {
            System.err.println("TESTSIGN=" + SecureNativeApi.testSign(ctx));
            return;
        }
        String canon = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/in.txt")), "UTF-8");
        String seed = new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/seed.txt")), "UTF-8").trim();
        System.err.println("[run] init cmd0");
        Object r0 = SecureNativeApi.doCommandNative(ctx, 0, seed.getBytes("UTF-8"), new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/appid.txt")),"UTF-8").trim().getBytes("UTF-8"), false);
        System.err.println("INIT=" + (r0 == null ? "null" : r0.toString()));
        if ("1".equals(System.getenv().getOrDefault("SIGN_EPDATA","0"))) {
            byte[] ep = SecureNativeApi.encryptPostData(System.getenv().getOrDefault("EPDATA","{}"), java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/appid.txt")));
            System.err.println("EP=" + (ep==null?"null":java.util.Base64.getEncoder().encodeToString(ep)));
        }
        if ("1".equals(System.getenv().getOrDefault("SIGN_WARMUP","0"))) {
            SecureNativeApi.doCommandNative(new android.content.Context(), 1, "warmup".getBytes("UTF-8"), null, false);
        }
        System.err.println("[run] calling doCommandNative");
        boolean md = "1".equals(System.getenv().getOrDefault("SIGN_MD","0"));
        Object r = SecureNativeApi.doCommandNative(new android.content.Context(), 1, canon.getBytes("UTF-8"), null, md);
        System.err.println("RESULT=" + (r == null ? "null" : r.toString()));
    }
}
