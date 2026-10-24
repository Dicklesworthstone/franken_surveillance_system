package android.content;
public class Context {
    private final android.content.res.AssetManager am = new android.content.res.AssetManager();
    private final android.content.pm.PackageManager pm = new android.content.pm.PackageManager();
    public android.content.res.AssetManager getAssets() { System.err.println("[ctx] getAssets"); return am; }
    public android.content.pm.PackageManager getPackageManager() { System.err.println("[ctx] getPackageManager"); return pm; }
    public String getPackageName() { System.err.println("[ctx] getPackageName"); try { return new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/package.txt")),"UTF-8").trim(); } catch (Exception e) { return "com.glazero.android"; } }
    public Context getApplicationContext() { return this; }
    public java.io.File getFilesDir() { return new java.io.File("/tmp"); }
    public java.io.File getCacheDir() { return new java.io.File("/tmp"); }
    public java.io.File getExternalFilesDir(String t) { return new java.io.File("/tmp"); }
    public android.content.pm.PackageInfo getPackageInfo(String n, int f) throws android.content.pm.PackageManager.NameNotFoundException { System.err.println("[ctx] getPackageInfo"); return new android.content.pm.PackageInfo(); }
}
