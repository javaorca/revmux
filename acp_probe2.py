import json, subprocess, time, sys

proc = subprocess.Popen(
    ["devin", "acp", "--agent-type", "review"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, bufsize=1, cwd=r"C:\Users\javao\.t3\worktrees\revmux\ef-906028d6",
)
proc.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":False,"writeTextFile":False},"terminal":False},"clientInfo":{"name":"probe","version":"0"}}}) + "\n")
proc.stdin.flush()
print("init resp:", proc.stdout.readline()[:200])
proc.stdin.close()
t0 = time.time()
rc = proc.wait(timeout=30)
print("exited after EOF in %.1fs rc=%s" % (time.time() - t0, rc))
