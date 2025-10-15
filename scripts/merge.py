#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, urllib.request, gzip, hashlib

SRC_FILE = "sources.txt"
OUT_DIR = "dist"; os.makedirs(OUT_DIR, exist_ok=True)

# ---------- 正则 ----------
R_BLANK    = re.compile(r'^\s*$')
R_COMMENT  = re.compile(r'^\s*(?:!|#)(?!@#)')
R_COSMETIC = re.compile(r'^\s*(?:##|#@#)')
R_HOSTS    = re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)\s*$')
R_DOMAIN   = re.compile(r'^\s*(?:\|\|)?([A-Za-z0-9._-]+\.[A-Za-z]{2,})(?:\^)?\s*$')

# AdGuard/AGH modifier 抽取（尽量宽松）
R_RULE_WITH_MOD = re.compile(r'^(?P<rule>.+?)\$(?P<mods>.+)$')
# dnsrewrite 语义：||d^$dnsrewrite=IP 或  ||d^$dnsrewrite=NOERROR;A;1.2.3.4
R_DNSREWRITE = re.compile(r'^\s*\|\|(?P<dom>[A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnsrewrite=(?P<val>.+)\s*$')
R_DNSTYPE    = re.compile(r'^\s*\|\|(?P<dom>[A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnstype=(?P<val>.+)\s*$')

def idna_norm(d:str)->str:
    try:
        return d.encode("idna").decode("ascii").lower().strip(".")
    except Exception:
        return d.lower().strip(".")

def fetch(url:str, timeout=60)->str:
    req = urllib.request.Request(url, headers={"User-Agent":"AGH-Merger/1.2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.getheader("Content-Encoding","").lower()=="gzip":
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="ignore")

def normalize_and_dedupe(all_lines:list, keep_idna=True):
    # 语义集合
    allow_domains  = set()               # @@||domain^  白名单域
    block_domains  = set()               # ||domain^    阻止域
    dnsrewrite_map = {}                  # domain -> set of rewrite strings
    dnstype_map    = {}                  # domain -> set of types (e.g. A,AAAA,TXT)
    raw_rules      = set()               # 其余复杂/正则/带修饰的网络规则（逐文本去重）

    # 计数
    total_before = 0

    for raw in all_lines:
        total_before += 1
        s = raw.strip().replace("\ufeff","")
        if R_BLANK.match(s) or R_COMMENT.match(s) or R_COSMETIC.match(s):
            continue

        # ---- 1) hosts / 纯域名：统一成 ||domain^（域名级去重）----
        m = R_HOSTS.match(s)
        if m:
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            block_domains.add(d);  continue

        m = R_DOMAIN.match(s)
        if m:
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            if s.startswith('@@'):
                allow_domains.add(d)
            else:
                block_domains.add(d)
            continue

        # ---- 2) AGH 专属：dnsrewrite / dnstype ----
        m = R_DNSREWRITE.match(s)
        if m:
            d = idna_norm(m.group("dom")) if keep_idna else m.group("dom").lower()
            v = m.group("val").strip()
            dnsrewrite_map.setdefault(d, set()).add(v)
            # 同时把域名计入“受控集”，便于后续冲突消解
            block_domains.add(d)
            continue

        m = R_DNSTYPE.match(s)
        if m:
            d = idna_norm(m.group("dom")) if keep_idna else m.group("dom").lower()
            v = m.group("val").strip()
            dnstype_map.setdefault(d, set()).add(v)
            block_domains.add(d)
            continue

        # ---- 3) 其它网络规则（保留文本、尽力抽域名同步到 block 集合用于域名级去重）----
        if s.startswith('@@'):
            # 白名单规则：保留文本，同时同步域名（若能抽到）
            m2 = R_DOMAIN.search(s)
            if m2:
                allow_domains.add(idna_norm(m2.group(1)) if keep_idna else m2.group(1).lower())
            raw_rules.add(s);  continue

        if s.startswith('||') or s.startswith('|') or ('$' in s) or (s.startswith('/') and s.endswith('/')):
            m2 = R_DOMAIN.search(s)
            if m2:
                d = idna_norm(m2.group(1)) if keep_idna else m2.group(1).lower()
                block_domains.add(d)
            raw_rules.add(s);  continue

        # 其它未知：忽略
        # print("ignored:", s)

    # ---- 4) 冲突处理：白名单优先（域名层面）----
    # 若 @@||d^ 存在，则移除该域名的阻止与重写/类型限制
    for d in list(allow_domains):
        block_domains.discard(d)
        dnsrewrite_map.pop(d, None)
        dnstype_map.pop(d, None)

    # ---- 5) 产出规范化列表（稳定排序）----
    # a) 纯域阻止 → 规则行
    block_rules = [f"||{d}^" for d in sorted(block_domains)]

    # b) dnsrewrite/dnstype 去重后输出（同一域相同值只保留一次）
    for d in sorted(dnsrewrite_map.keys()):
        for v in sorted(dnsrewrite_map[d]):
            block_rules.append(f"||{d}^$dnsrewrite={v}")
    for d in sorted(dnstype_map.keys()):
        for v in sorted(dnstype_map[d]):
            block_rules.append(f"||{d}^$dnstype={v}")

    # c) 其它网络规则文本去重
    rules_sorted = sorted(raw_rules)

    # d) 纯域名/hosts 版本（只基于最终阻止集合，不含被白名单覆盖的域）
    domains = sorted(set(block_domains) | set(dnsrewrite_map.keys()) | set(dnstype_map.keys()))

    # 统计
    total_after = len(block_rules) + len(rules_sorted)
    stats = {
        "total_before": total_before,
        "total_after": total_after,
        "dedup_removed": max(total_before - total_after, 0),
    }
    return block_rules, rules_sorted, domains, stats

def header(title, sources):
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    h = [
        f"! {title}",
        f"! Generated at: {now}",
        f"! Sources:"
    ] + [f"!  - {s}" for s in sources] + [
        "! Notes:",
        "! - Cosmetic rules (##, #@#) removed for DNS use.",
        "! - Whitelist (@@) has higher priority than block/dnsrewrite/dnstype.",
        ""
    ]
    return "\n".join(h)

def write_outputs(block_rules, raw_rules, domains, sources):
    # 1) Adblock 合并版
    with open(os.path.join(OUT_DIR,"merged_adblock.txt"),"w",encoding="utf-8") as f:
        f.write(header("Unified Adblock list for AdGuard Home (DNS)", sources))
        for r in block_rules: f.write(r+"\n")
        for r in raw_rules:   f.write(r+"\n")

    # 2) hosts
    with open(os.path.join(OUT_DIR,"merged_hosts.txt"),"w",encoding="utf-8") as f:
        f.write("# 0.0.0.0 hosts merged\n")
        for d in domains: f.write(f"0.0.0.0 {d}\n")

    # 3) 纯域名
    with open(os.path.join(OUT_DIR,"merged_domains.txt"),"w",encoding="utf-8") as f:
        for d in domains: f.write(d+"\n")

def main():
    if not os.path.exists(SRC_FILE):
        raise SystemExit("sources.txt not found.")

    # 读取源
    sources = []
    with open(SRC_FILE,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            u=line.strip()
            if u and not u.startswith("#"): sources.append(u)

    # 拉取
    lines=[]
    for url in sources:
        try:
            txt = fetch(url)
            lines.extend(txt.splitlines())
            print("OK:", url)
        except Exception as e:
            print("FAIL:", url, e)

    # 规范化 + 去重 + 冲突解决
    block_rules, raw_rules, domains, stats = normalize_and_dedupe(lines)

    # 写出
    write_outputs(block_rules, raw_rules, domains, sources)

   # 校验 + 统计
for name in ("merged_adblock.txt","merged_hosts.txt","merged_domains.txt"):
    p = os.path.join(OUT_DIR, name)
    with open(p, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()[:16]
    print(f"Wrote {p}  sha256[:16]={sha}")

print(f"去重前: {stats['total_before']} 行")
print(f"去重后: {stats['total_after']} 行")
if stats["total_before"] > 0:
    pct = (stats["total_before"] - stats["total_after"]) / stats["total_before"] * 100
else:
    pct = 0.0
print(f"去掉重复/无效: {stats['dedup_removed']} 行 ({pct:.2f}%)")

if __name__=="__main__":
    main()
