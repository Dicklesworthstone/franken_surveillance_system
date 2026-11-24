package android.content;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Context {
    private final android.content.res.AssetManager am = new android.content.res.AssetManager();
    private final android.content.pm.PackageManager pm = new android.content.pm.PackageManager();
    public android.content.res.AssetManager getAssets() { System.err.println("[ctx] getAssets"); return am; }
    public android.content.pm.PackageManager getPackageManager() { System.err.println("[ctx] getPackageManager"); return pm; }
    public String getPackageName() {
        System.err.println("[ctx] getPackageName");
        try {
            Path p = Path.of("/data/package.txt");
            if (!Files.isRegularFile(p)) {
                p = Path.of("/w/cfg/package.txt");
            }
            if (Files.isRegularFile(p)) {
                return new String(Files.readAllBytes(p), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        return "com.glazero.android";
    }
    public Context getApplicationContext() { return this; }
    public java.io.File getFilesDir() { return new java.io.File("/tmp"); }
    public java.io.File getCacheDir() { return new java.io.File("/tmp"); }
    public java.io.File getExternalFilesDir(String t) { return new java.io.File("/tmp"); }
    public android.content.pm.PackageInfo getPackageInfo(String n, int f) throws android.content.pm.PackageManager.NameNotFoundException { System.err.println("[ctx] getPackageInfo"); return new android.content.pm.PackageInfo(); }
}
