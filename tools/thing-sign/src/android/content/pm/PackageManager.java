package android.content.pm;
public class PackageManager {
    public static class NameNotFoundException extends Exception {}
    public android.content.pm.PackageInfo getPackageInfo(String n, int f) throws NameNotFoundException { return new android.content.pm.PackageInfo(); }
    public String getPackageName() { return "com.glazero.android"; }
}
