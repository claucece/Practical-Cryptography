#!/usr/bin/env python3
import socket, ssl, sys, time

host, port, delay = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
ctx = ssl.create_default_context()
if len(sys.argv) > 4:
    ctx.load_verify_locations(sys.argv[4])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3

inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(inb, outb, server_hostname=host)
sock = socket.create_connection((host, port))
t0 = time.time()

while True:                                   # ClientHello ... server flight
    try:
        tls.do_handshake()
        break                                 # client side done; Finished is in outb
    except ssl.SSLWantReadError:
        out = outb.read()
        if out:
            sock.sendall(out)
        data = sock.recv(65536)
        if not data:
            sys.exit("server closed the connection during the handshake")
        inb.write(data)

print(f"server flight processed after {time.time() - t0:.3f}s")
print(f"sleeping {delay}s before sending the client Finished (this is the '2PC time')")
time.sleep(delay)
sock.sendall(outb.read())                     # client Finished

try:                                          # is the server still there?
    tls.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    sock.sendall(outb.read())
    sock.settimeout(10)
    while True:
        data = sock.recv(65536)
        if not data:
            sys.exit("server closed the connection: it gave up waiting")
        inb.write(data)
        try:
            reply = tls.read(4096)
            break
        except ssl.SSLWantReadError:
            continue
    print("server still answered:", reply.split(b"\r\n")[0].decode(errors="replace"))
except (ssl.SSLError, OSError) as e:
    print("server gave up:", e)
