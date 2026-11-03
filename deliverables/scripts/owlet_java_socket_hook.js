/*
 * Owlet auth wire-path discriminator, Java + native layers in one capture.
 *
 * The SDK logs "Authenticating with Camera" with the minted 32-hex password and then AV_ER_TIMEOUT,
 * while the classic TUTK entry points (libAVAPIs avClientStart*, libTUTKGlobalAPIs
 * LinuxTConnection_*) never fire. This script answers *which layer the auth rides*:
 *
 *   - java.net.Socket connect / SocketOutputStream.write / SocketInputStream.read — the mint and
 *     any HTTP(S) control plane;
 *   - libc sendto / recvfrom / send / recv — the IOTC/TUTK transport, filtered to the camera's
 *     session and search ports so relay keepalive noise does not drown the exchange.
 *
 * Dumps are capped at DUMP bytes with hex+ASCII. A frame that appears in neither layer is the
 * answer that the path is elsewhere.
 *
 *   owlet_auth_capture.py --pid <pid> --out /tmp/owlet_cap/x.log --seconds 120
 */
const DUMP = 704;   // 704 B covers the 576 B 0x2043 registration; 320 truncated it
const PORTS = [36167, 63616];   // camera session socket, LAN-search listener
const SELF_IP = "192.168.4.163";

// frida 17 exposes a Java byte[] / native buffer as an index-only proxy: no slice(), signed values
function take(buf, off, len) {
  const n = Math.min(len, DUMP), out = [];
  for (let i = 0; i < n; i++) out.push(buf.add ? buf.add(off + i).readU8() : (buf[off + i] & 0xff));
  return out;
}

function ascii(bytes) {
  let s = "";
  for (const b of bytes) s += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
  return s;
}

function hex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stamp() {
  return new Date().toISOString().substr(11, 12);
}

function addrOf(sock) {
  try { return String(sock.getRemoteSocketAddress()); } catch (e) { return "?"; }
}

function sockaddrPort(p) {
  try {
    // sockaddr_in, little-endian: family in the low byte, port at offset 2 (AF_INET only)
    if (p.readU8() !== 2) return 0;
    return (p.add(2).readU8() << 8) | p.add(3).readU8();
  } catch (e) { return 0; }
}

// native first: it must attach even when the Java bridge is slow to build
  // ---- native transport (the IOTC/TUTK path) ------------------------------------------------
  // Connected UDP sockets use send/recv with no sockaddr, so the peer is resolved once per fd
  // with getpeername and cached; sendto/recvfrom carry the address in arg 4.
  const PEERS = {};
  const getpeername = new NativeFunction(Module.getGlobalExportByName("getpeername"),
                                         "int", ["int", "pointer", "pointer"]);
  function peerPort(fd) {
    if (fd in PEERS) return PEERS[fd];
    const sa = Memory.alloc(128), len = Memory.alloc(4);
    len.writeU32(128);
    PEERS[fd] = getpeername(fd, sa, len) === 0 ? sockaddrPort(sa) : -1;
    return PEERS[fd];
  }

  // keepalives are 4/24 B; anything >= 40 B is a real frame, and camera ports are always kept
  const MIN = 40;
  function keep(port, len) {
    return PORTS.includes(port) || len >= MIN;
  }

  function report(dir, fd, port, len, buf, n) {
    const take_ = n === undefined ? len : Math.min(n, len);
    const b = take(buf, 0, take_);
    console.log(`[${stamp()}] ${dir} fd=${fd} :${port > 0 ? port : "?"} len=${take_}\n` +
                `         hex=${hex(b)}\n         asc=${ascii(b)}`);
  }

  for (const name of ["sendto", "send"]) {
    Interceptor.attach(Module.getGlobalExportByName(name), {
      onEnter(args) {
        const fd = args[0].toInt32();
        const len = args[2].toInt32();
        const port = name === "sendto" ? sockaddrPort(args[4]) : peerPort(fd);
        if (!keep(port, len)) return;
        report(name, fd, port, len, args[1]);
      },
    });
  }

  for (const name of ["recvfrom", "recv"]) {
    Interceptor.attach(Module.getGlobalExportByName(name), {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.port = name === "recvfrom" ? sockaddrPort(args[4]) : peerPort(this.fd);
      },
      onLeave(ret) {
        const n = ret.toInt32();
        if (n <= 0 || !keep(this.port, n)) return;
        report(name, this.fd, this.port, this.len, this.buf, n);
      },
    });
  }

function attachJava(attempt) {
  try {
    console.log("[hook] java socket layer attached");

  const Socket = Java.use("java.net.Socket");
  Socket.connect.overload("java.net.SocketAddress").implementation = function (addr) {
    console.log(`[${stamp()}] CONNECT ${addr}`);
    return this.connect(addr);
  };
  Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (addr, t) {
    console.log(`[${stamp()}] CONNECT ${addr} timeout=${t}`);
    return this.connect(addr, t);
  };

  const Out = Java.use("java.net.SocketOutputStream");
  Out.socketWrite0.implementation = function (sock, buf, off, len) {
    let slice = [];
    try { slice = take(buf, off, len); } catch (e) { /* dump only */ }
    console.log(`[${stamp()}] WRITE ${addrOf(sock)} len=${len}\n` +
                `         hex=${hex(slice)}\n         asc=${ascii(slice)}`);
    return this.socketWrite0(sock, buf, off, len);
  };

  const In = Java.use("java.net.SocketInputStream");
  In.socketRead0.implementation = function (sock, buf, off, len, timeout) {
    const n = this.socketRead0(sock, buf, off, len, timeout);
    if (n > 0) {
      let slice = [];
      try { slice = take(buf, off, n); } catch (e) { /* dump only */ }
      console.log(`[${stamp()}] READ  ${addrOf(sock)} len=${n}\n` +
                  `         hex=${hex(slice)}\n         asc=${ascii(slice)}`);
    }
    return n;
  };

  const SSL = Java.use("javax.net.ssl.SSLSocket");
  SSL.startHandshake.implementation = function () {
    console.log(`[${stamp()}] TLS handshake ${addrOf(this)}`);
    return this.startHandshake();
  };
  } catch (e) {
    console.log(`[hook] java attach failed (${e}); retry ${attempt}`);
    if (attempt < 20) setTimeout(() => attachJava(attempt + 1), 1500);
  }
}
attachJava(1);
