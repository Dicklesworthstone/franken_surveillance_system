package android.content.pm;
public class Signature {
    public byte[] toByteArray() {
        try { return java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/data/cert.der")); }
        catch (Exception e) { return new byte[0]; }
    }
}
