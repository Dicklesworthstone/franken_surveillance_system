package android.content.pm;
public class Signature {
    public byte[] toByteArray() {
        try { byte[] b = java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/cert.der")); System.err.println("[sig] toByteArray " + b.length); return b; }
        catch (Exception e) { System.err.println("[sig] fail " + e); return new byte[0]; }
    }
}
