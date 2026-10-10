"""删除 server.js 里多余的 express.json() 行。
createMcpExpressApp 已经装了 body parser，再加一个会导致请求体被消费两次 → 500。"""
from pathlib import Path
import re

p = Path("src/server.js")
t = p.read_text(encoding="utf-8")

if "already installs a body parser" in t:
    print("already fixed")
    raise SystemExit(0)

# 匹配:app.use(express.json({ limit: '1mb' }));（允许空格差异）
pattern = re.compile(r"^app\.use\(express\.json\(.*?\)\);\s*$", re.MULTILINE)
matches = pattern.findall(t)
if not matches:
    print("FAIL: 找不到 app.use(express.json(...)) 那一行")
    raise SystemExit(1)

print(f"找到 {len(matches)} 处:")
for m in matches:
    print(f"  {m.strip()}")

comment = "// Note: createMcpExpressApp already installs a body parser. Adding express.json() here would double-consume the request stream and cause a 500 error on /mcp."
t = pattern.sub(comment, t)
p.write_text(t, encoding="utf-8")

# 复验
t2 = p.read_text(encoding="utf-8")
print()
print("复验:")
print("  注释已插入:       ", "already installs a body parser" in t2)
print("  express.json 已移除:", "express.json" not in t2)