#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, time, urllib.request, gzip, hashlib

SRC_FILE = "sources.txt"
OUT_DIR = "dist"; os.makedirs(OUT_DIR, exist_ok=True)

# ====== 规则识别 ======
R_BLANK    = re.compile(r'^\s*$')
R_COMMENT  = re.compile(r'^\s*(?:!|#)(?!@#)')      # ! 或 #（排除 #@#）
R_COSMETIC = re.compile(r'^\s*(?:##|#@#)')        # 美容规则，DNS无用
R_HOSTS    = re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)\s*$')
R_DOMAIN   = re.compile(r'^\s*(?:\|\|)?([A-Za-z0-9._-]+\.[A-Za-z]{2,})(?:\^)?\s*$')

def idna_norm(d:str)->str:
    # 可选：把中文/特殊域名转成 punycode；普通域名不受影响
    try:
        return d.encode("idna").decode("ascii").lower().strip(".")
    except Exception:
        return d.lower().strip(".")

def fetch(url:str, timeout=60)->str:
    req = urllib.request.Request(url, headers={"User-Agent":"AGH-Merger/1.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.getheader("Content-Encoding","").lower()=="gzip":
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="ignore")

def normalize_and_dedupe(all_lines:list, keep_idna=True):
    allow = set()     # @@ 例外域名/规则
    block = set()     # 阻止域名（标准化为 ||domain^）
    raw_rules = set() # 其它保留的网络规则（带$修饰/正则等）

    for raw in all_lines:
        s = raw.strip().replace("\ufeff","")
        if R_BLANK.match(s) or R_COMMENT.match(s) or R_COSMETIC.match(s):
            continue

        # 1) 先抓 hosts & 纯域名 → 统一为 ||domain^
        m = R_HOSTS.match(s)
        if m:
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            block.add(f"||{d}^");  continue

        m = R_DOMAIN.match(s)
        if m:
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            # 是否白名单域名（很少见，通常是 @@||domain^）
            if s.startswith('@@'): allow.add(d)
            else:                  block.add(f"||{d}^")
            continue

        # 2) 标准 Adblock 规则
        if s.startswith('@@'):
            # 例外规则：尽力抽域名，抽到就记到 allow；规则本身也保留
            m = R_DOMAIN.search(s)
            if m:
                allow.add(idna_norm(m.group(1)) if keep_idna else m.group(1).lower())
            raw_rules.add(s);  continue

        if s.startswith('||') or s.startswith('|') or ('$' in s) or (s.startswith('/') and s.endswith('/')):
            # 网络规则：尽力抽域名同步一份到 block（用于域名级去重），原规则也保留
            m = R_DOMAIN.search(s)
            if m:
                d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
                block.add(f"||{d}^")
            raw_rules.add(s);  continue

        # 其它未知语法：丢弃（可按需改为 raw_rules.add(s)）
        # print("ignored:", s)

    # ====== 冲突处理：白名单优先 ======
    # 如果 @@ 了 example.com，则从 block 中移除 "||example.com^"
    # 注意：不合并父子域名，避免误允许（example.com 与 a.example.com 视为不同）
    final_block = {r for r in block if idna_norm(r[2:-1]) not in allow}

    # 输出列表：稳定排序
    block_sorted = sorted(final_block)
    rules_sorted = sorted(raw_rules)

    # 纯域名/hosts 版本
    domains = sorted({r[2:-1] for r in final_block})
    return block_sorted, rules_sorted, domains

def write_outputs(block_rules, raw_rules, domains, sources):
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    head = [
        f"! Unified Adblock list for AdGuardHome (DNS)",
        f"! Generated at: {now}",
        f"! Sources:"
    ] + [f"!  - {s}" for s in sources] + ["! White-list has higher priority.", ""]

    # 1) Adblock 合并版（域名阻止 + 复杂网络规则）
    with open(os.path.join(OUT_DIR,"merged_adblock.txt"),"w",encoding="utf-8") as f:
        f.write("\n".join(head))
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
    block_rules, raw_rules, domains = normalize_and_dedupe(lines)

    # 写出
    write_outputs(block_rules, raw_rules, domains, sources)

    # 校验摘要
    for name in ("merged_adblock.txt","merged_hosts.txt","merged_domains.txt"):
        p=os.path.join(OUT_DIR,name)
        with open(p,"rb") as f: sha=hashlib.sha256(f.read()).hexdigest()[:16]
        print(f"Wrote {p}  sha256[:16]={sha}")

if __name__=="__main__":
    main()
