import os, random, socket, struct, subprocess, sys, time

TUN = "build-asan/lc-tunnel"
LOG = "/tmp/storm.err"
random.seed(1)

p = subprocess.Popen(
    [TUN, "build/chrome.fpt", "xhttp-test", "8443", "www.avito.ru",
     os.environ.get("PBK", "PUT-THE-RIG-PUBLIC-KEY-HERE-see-test-donor-README"), "0123456789abcdef",
     "11111111-2222-3333-4444-555555555555", "19099", "-t", "127.0.0.1:9"],
    stdout=open("/tmp/storm.out","w"), stderr=open(LOG, "w"))
time.sleep(1.5)
if p.poll() is not None:
    print("DID NOT START:", open(LOG).read()[:300]); sys.exit(1)

rounds, opened, rst, graceful = 0, 0, 0, 0
t_end = time.time() + 30
while time.time() < t_end:
    batch = []
    for _ in range(8):
        try:
            c = socket.create_connection(("127.0.0.1", 19099), 2)
            c.setblocking(False)
            batch.append(c); opened += 1
        except OSError:
            pass
    # A little data, so the session reaches the carrying stage instead of dying empty.
    for c in batch:
        try: c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        except OSError: pass
    time.sleep(0.35)  # let the handshake reach ST_OPEN
    for c in batch:
        try: c.recv(65536)
        except OSError: pass
    random.shuffle(batch)
    for c in batch:
        try:
            if random.random() < 0.5:
                # RST: a teardown with unread data still queued, which is the nastiest case.
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                rst += 1
            else:
                graceful += 1
            c.close()
        except OSError: pass
    rounds += 1
    if rounds % 20 == 0: time.sleep(0.05)

time.sleep(2)
alive = p.poll() is None
p.terminate(); time.sleep(0.5); p.kill()
err = open(LOG, encoding="utf-8", errors="replace").read()
bad = [l for l in err.splitlines() if "ERROR:" in l or "runtime error" in l or "SUMMARY:" in l]
print("rounds %d, opened %d (RST %d, politely %d)" % (rounds, opened, rst, graceful))
print("process alive at the end: %s" % ("yes" if alive else "NO"))
print("sanitiser reports: %d" % len(bad))
for l in bad[:6]: print("   " + l)

# --- getting the resources back -----------------------------------------------
# Whether the state returns to where it started. On a router that matters more than the peak: a leak
# of a kilobyte per connection is invisible for a day and fatal within a week.
