package android.content.pm;

import java.nio.file.Files;
import java.nio.file.Path;

public class Signature {
    public byte[] toByteArray() {
        try {
            Path p = Path.of("/data/cert.der");
            if (!Files.isRegularFile(p)) {
                p = Path.of("/w/cfg/cert.der");
            }
            byte[] b = Files.readAllBytes(p);
            System.err.println("[sig] toByteArray " + b.length);
            return b;
        } catch (Exception e) {
            System.err.println("[sig] fail " + e);
            return new byte[0];
        }
    }
}
