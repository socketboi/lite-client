import os, re, socket, struct, subprocess, sys, time, random
random.seed(7)
LOG="/tmp/rec.err"
p = subprocess.Popen(["build/lc-tunnel","build/chrome.fpt","xhttp-test","8443","www.avito.ru",
  os.environ.get("PBK", "PUT-THE-RIG-PUBLIC-KEY-HERE-see-test-donor-README"),"0123456789abcdef",
  "11111111-2222-3333-4444-555555555555","19099","-t","127.0.0.1:9"],
  stdout=open("/tmp/rec.out","w"), stderr=open(LOG,"w"))
time.sleep(1.5)
def rss(): return int(re.search(r"VmRSS:\s+(\d+)", open("/proc/%d/status"%p.pid).read()).group(1))
def fds(): return len(os.listdir("/proc/%d/fd"%p.pid))
base = (rss(), fds()); print("before the load: RSS %d kB, fd %d" % base)
peak = base
for rnd in range(60):
    b=[]
    for _ in range(10):
        try:
            c=socket.create_connection(("127.0.0.1",19099),2); c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); b.append(c)
        except OSError: pass
    time.sleep(0.3)
    peak = (max(peak[0],rss()), max(peak[1],fds()))
    for c in b:
        if random.random()<0.5: c.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
        c.close()
print("at the peak:     RSS %d kB, fd %d" % peak)
time.sleep(20)
after=(rss(),fds()); print("after the close: RSS %d kB, fd %d" % after)
print("delta:           RSS %+d kB, fd %+d" % (after[0]-base[0], after[1]-base[1]))
print("sessions opened: %d" % open("/tmp/rec.out").read().count("opened"))
p.terminate(); time.sleep(0.4); p.kill()
err=open(LOG,errors="replace").read()
print("sanitiser: %d reports" % len([l for l in err.splitlines() if "ERROR:" in l or "runtime error" in l]))
