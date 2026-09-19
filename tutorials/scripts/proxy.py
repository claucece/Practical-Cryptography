import socket, threading, sys

L, T, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", L)); srv.listen(1)
c, _ = srv.accept(); s = socket.create_connection(("127.0.0.1", T))

def pump(a, b, log):
    with open(log, "wb") as f:
        while True:
            try: d = a.recv(65536)
            except OSError: break
            if not d: break
            f.write(d); f.flush()
            try: b.sendall(d)
            except OSError: break
    try: b.shutdown(socket.SHUT_WR)
    except OSError: pass

t1 = threading.Thread(target=pump, args=(c, s, out + ".c2s")); t2 = threading.Thread(target=pump, args=(s, c, out + ".s2c"))
t1.start(); t2.start(); t1.join(); t2.join()
