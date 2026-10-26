import json, subprocess, sys, threading, time

proc = subprocess.Popen(
    ["devin", "acp", "--agent-type", "review"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, bufsize=1, cwd=r"C:\Users\javao\.t3\worktrees\revmux\ef-906028d6",
)

def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()

def readline(timeout=60):
    line = proc.stdout.readline()
    return line

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": 1,
    "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False},
    "clientInfo": {"name": "revmux-probe", "version": "0.0.0"},
}})

t0 = time.time()
lines = []
for _ in range(40):
    l = readline()
    if not l:
        break
    lines.append(l.rstrip())
    try:
        msg = json.loads(l)
    except Exception:
        continue
    if msg.get("id") == 1:
        print("INIT RESPONSE:", json.dumps(msg)[:2000])
        break

send({"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": r"C:\Users\javao\.t3\worktrees\revmux\ef-906028d6", "mcpServers": []}})
sid = None
while True:
    l = readline()
    if not l:
        break
    msg = json.loads(l)
    if msg.get("id") == 2:
        print("SESSION/NEW:", json.dumps(msg)[:2000])
        sid = msg["result"]["sessionId"]
        break

if sid:
    send({"jsonrpc": "2.0", "id": 3, "method": "session/prompt", "params": {
        "sessionId": sid,
        "prompt": [{"type": "text", "text": "Run `git log --oneline -2` then reply with only the word done"}],
    }})
    while True:
        l = readline()
        if not l:
            break
        sys.stdout.write(l)
        sys.stdout.flush()
        msg = json.loads(l)
        if msg.get("method") == "session/request_permission":
            opts = msg["params"].get("options", [])
            allow = next((o for o in opts if "allow" in o.get("kind", "")), opts[0] if opts else None)
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {"outcome": {"outcome": "selected", "optionId": allow["optionId"]}}})
            print(">>> answered permission:", allow)
        elif "id" in msg and "method" in msg:
            send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found"}})
            print(">>> rejected incoming:", msg["method"])
        if msg.get("id") == 3:
            print("PROMPT DONE:", json.dumps(msg)[:500])
            break

print("elapsed", time.time() - t0)
proc.kill()
