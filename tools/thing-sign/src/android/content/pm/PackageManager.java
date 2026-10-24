package android.content.pm;
public class PackageManager {
    public static class NameNotFoundException extends Exception {}
    public android.content.pm.PackageInfo getPackageInfo(String n, int f) throws NameNotFoundException { System.err.println("[pm] getPackageInfo " + n); return new android.content.pm.PackageInfo(); }
    public String getPackageName() { return "com.glazero.android"; }
}
