import com.thingclips.smart.security.jni.SecureNativeApi;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Run {
    static {
        System.loadLibrary("c++_shared");
        System.loadLibrary("thing_security_algorithm");
        System.loadLibrary("thing_security");
        System.err.println("[run] libs loaded");
    }

    private static byte[] readDataOrDefault(String name) throws IOException {
        Path override = Path.of("/data", name);
        if (Files.isRegularFile(override)) {
            return Files.readAllBytes(override);
        }
        return Files.readAllBytes(Path.of("/w/cfg", name));
    }

    private static String readTextOrDefault(String name) throws IOException {
        return new String(readDataOrDefault(name), StandardCharsets.UTF_8);
    }

    public static void main(String[] a) throws Exception {
        android.content.Context ctx = new android.content.Context();
        if (a.length > 0 && a[0].equals("digest")) {
            String msg = a.length > 1 ? a[1] : "abc";
            String key = a.length > 2 ? a[2] : "key";
            System.err.println("DIGEST=" + SecureNativeApi.computeDigest(msg, key));
            return;
        }
        if (a.length > 0 && a[0].equals("enc")) {
            String sd = readTextOrDefault("seed.txt").trim();
            String ai = readTextOrDefault("appid.txt").trim();
            SecureNativeApi.doCommandNative(ctx, 0, sd.getBytes(StandardCharsets.UTF_8), ai.getBytes(StandardCharsets.UTF_8), false);
            SecureNativeApi.doCommandNative(ctx, 1, "warmup".getBytes(StandardCharsets.UTF_8), null, false);
            byte[] k = SecureNativeApi.getEncryptoKey(a[1], a.length > 2 ? a[2] : null);
            StringBuilder sb = new StringBuilder();
            if (k != null) for (byte b : k) sb.append(String.format("%02x", b));
            System.err.println("KEY=" + sb);
            return;
        }
        if (a.length > 0 && a[0].equals("chkey")) {
            String sd = readTextOrDefault("seed.txt").trim();
            String ai2 = readTextOrDefault("appid.txt").trim();
            SecureNativeApi.doCommandNative(ctx, 0, sd.getBytes(StandardCharsets.UTF_8), ai2.getBytes(StandardCharsets.UTF_8), false);
            SecureNativeApi.doCommandNative(ctx, 1, "warmup".getBytes(StandardCharsets.UTF_8), null, false);
            String k = SecureNativeApi.getChKey(new android.content.Context(), ai2.getBytes(StandardCharsets.UTF_8));
            System.err.println("CHKEY=" + k);
            return;
        }
        if (a.length > 0 && a[0].equals("test")) {
            System.err.println("TESTSIGN=" + SecureNativeApi.testSign(ctx));
            return;
        }
        String canon = readTextOrDefault("in.txt").trim();
        String seed = readTextOrDefault("seed.txt").trim();
        String appid = readTextOrDefault("appid.txt").trim();
        System.err.println("[run] init cmd0");
        Object r0 = SecureNativeApi.doCommandNative(ctx, 0, seed.getBytes(StandardCharsets.UTF_8), appid.getBytes(StandardCharsets.UTF_8), false);
        System.err.println("INIT=" + (r0 == null ? "null" : r0.toString()));
        if ("1".equals(System.getenv().getOrDefault("SIGN_EPDATA", "0"))) {
            byte[] ep = SecureNativeApi.encryptPostData(System.getenv().getOrDefault("EPDATA", "{}"), appid.getBytes(StandardCharsets.UTF_8));
            System.err.println("EP=" + (ep == null ? "null" : java.util.Base64.getEncoder().encodeToString(ep)));
        }
        if ("1".equals(System.getenv().getOrDefault("SIGN_WARMUP", "0"))) {
            SecureNativeApi.doCommandNative(new android.content.Context(), 1, "warmup".getBytes(StandardCharsets.UTF_8), null, false);
        }
        System.err.println("[run] calling doCommandNative");
        boolean md = "1".equals(System.getenv().getOrDefault("SIGN_MD", "0"));
        Object r = SecureNativeApi.doCommandNative(new android.content.Context(), 1, canon.getBytes(StandardCharsets.UTF_8), null, md);
        System.err.println("RESULT=" + (r == null ? "null" : r.toString()));
    }
}
