#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard Home 专用过滤规则合并与去重
- 仅保留 AGH 支持的 DNS 级规则
- 白名单优先（域 + 全部子域）
- 父域覆盖子域（可选）
- 统一 IDNA（punycode）、稳定排序
输出：
- dist/merged_adblock.txt  （AGH 可直接订阅）
- dist/merged_hosts.txt    （0.0.0.0 hosts）
- dist/merged_domains.txt  （纯域名清单）
"""

import os, re, time, urllib.request, gzip, hashlib, sys

# ========= 配置 =========
SRC_FILE  = "sources.txt"
OUT_DIR   = "dist"
KEEP_IDNA = True                 # True: 域名统一到 punycode，小写，无尾点
ENABLE_PARENT_COLLAPSE = True    # True: 父域覆盖子域去冗余
TIMEOUT   = 90

# 常见多级公共后缀（避免把 public suffix 当父域合并）
COMMON_MULTI_PSL = {
    "co.uk", "ac.uk", "gov.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ed.jp", "go.jp", "gr.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn"
}

os.makedirs(OUT_DIR, exist_ok=True)

# ========= 正则 =========
R_BLANK    = re.compile(r'^\s*$')
R_COMMENT  = re.compile(r'^\s*(?:!|#)(?!@#)')           # # 和 ! 开头（不包含 #@# 反元素）
R_COSMETIC = re.compile(r'^\s*(?:##|#@#)')              # 元素/外观规则
R_HOSTS    = re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)\s*$')
R_DOMAIN   = re.compile(r'^\s*(?:\|\|)?([A-Za-z0-9._-]+\.[A-Za-z]{2,})(?:\^)?\s*$')
R_DNSREWRITE = re.compile(r'^\s*\|\|(?P<dom>[A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnsrewrite=(?P<val>.+)\s*$')
R_DNSTYPE    = re.compile(r'^\s*\|\|(?P<dom>[A-Za-z0-9._-]+\.[A-Za-z]{2,})\^\$dnstype=(?P<val>.+)\s*$')

# ========= 工具 =========
def idna_norm(d: str) -> str:
    d = d.strip().strip(".")
    try:
        return d.encode("idna").decode("ascii").lower()
    except Exception:
        return d.lower()

def fetch(url: str, timeout=TIMEOUT) -> str:
    req = urllib.request.Request(url, headers={"User-Agent":"AGH-Merger/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.getheader("Content-Encoding","").lower()=="gzip":
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="ignore")

def header(title, sources):
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    h = [
        f"! {title}",
        f"! Generated at: {now}",
        f"! Sources:"
    ] + [f"!  - {s}" for s in sources] + [
        "! Notes:",
        "! - AGH-only DNS rules retained (||, @@||, $dnsrewrite, $dnstype, hosts).",
        "! - Cosmetic rules (##, #@#) and browser-only modifiers are removed.",
        "! - Whitelist (@@) wins over block/dnsrewrite/dnstype for domain & subdomains.",
        ""
    ]
    return "\n".join(h)

def _is_subdomain_of(child: str, parent: str) -> bool:
    child = child.strip(".")
    parent = parent.strip(".")
    return child == parent or child.endswith("." + parent)

def _split_labels(d: str):
    return d.strip(".").split(".")

def _is_public_suffix_like(d: str) -> bool:
    # 粗略判断：单标签（无意义）或在内置多级 PSL 集内
    d = d.lower().strip(".")
    if d in COMMON_MULTI_PSL:
        return True
    return len(_split_labels(d)) <= 1

def _registrable_domain(d: str) -> str:
    # 简化：若末尾两段是常见多级 PSL，则取末尾三段；否则取末尾两段
    # 仅用于父域折叠时做保守判断（避免把 registrable 边界合并错）
    labs = _split_labels(d.lower())
    if len(labs) < 2:
        return d
    last2 = ".".join(labs[-2:])
    if last2 in COMMON_MULTI_PSL and len(labs) >= 3:
        return ".".join(labs[-3:])
    return last2

# ========= 核心规范化/去重 =========
def normalize_and_dedupe(all_lines: list, keep_idna=KEEP_IDNA):
    allow_domains  = set()    # @@||domain^
    block_domains  = set()    # ||domain^（含 hosts 归并）
    dnsrewrite_map = {}       # domain -> set(values)
    dnstype_map    = {}       # domain -> set(values)

    # 统计
    total_before = 0
    count_ignored = 0
    count_hosts = count_plain = count_dnsrewrite = count_dnstype = 0

    for raw in all_lines:
        total_before += 1
        s = raw.strip().replace("\ufeff","")
        if R_BLANK.match(s) or R_COMMENT.match(s) or R_COSMETIC.match(s):
            count_ignored += 1
            continue

        # hosts → 阻止域
        m = R_HOSTS.match(s)
        if m:
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            if not _is_public_suffix_like(d):
                block_domains.add(d)
                count_hosts += 1
            else:
                count_ignored += 1
            continue

        # 纯域名 / ||domain^ / @@||domain^（不含 $、不含 /regex/）
        m = R_DOMAIN.match(s)
        if m and ('$' not in s) and not (s.startswith('/') and s.endswith('/')):
            d = idna_norm(m.group(1)) if keep_idna else m.group(1).lower()
            if _is_public_suffix_like(d):
                count_ignored += 1
                continue
            if s.startswith('@@'):
                allow_domains.add(d)
            else:
                block_domains.add(d)
            count_plain += 1
            continue

        # AGH 的 DNS 修饰：dnsrewrite / dnstype
        m = R_DNSREWRITE.match(s)
        if m:
            d = idna_norm(m.group("dom")) if keep_idna else m.group("dom").lower()
            if _is_public_suffix_like(d):
                count_ignored += 1
                continue
            v = m.group("val").strip()
            dnsrewrite_map.setdefault(d, set()).add(v)
            block_domains.add(d)  # 记入“有规则”的域，方便统一折叠
            count_dnsrewrite += 1
            continue

        m = R_DNSTYPE.match(s)
        if m:
            d = idna_norm(m.group("dom")) if keep_idna else m.group("dom").lower()
            if _is_public_suffix_like(d):
                count_ignored += 1
                continue
            v = m.group("val").strip()
            dnstype_map.setdefault(d, set()).add(v)
            block_domains.add(d)
            count_dnstype += 1
            continue

        # 其它（浏览器层修饰、/regex/、管线、脚本等）丢弃
        count_ignored += 1

    # ===== 白名单优先：移除被白名单覆盖的阻止/重写/类型限制 =====
    allow_sorted = sorted(allow_domains)
    def allowed(d):
        # @@||example.com^ 放行 example.com 及全部子域
        for a in allow_sorted:
            if _is_subdomain_of(d, a):
                return True
        return False

    if allow_domains:
        block_domains = {d for d in block_domains if not allowed(d)}
        for d in list(dnsrewrite_map.keys()):
            if allowed(d):
                dnsrewrite_map.pop(d, None)
        for d in list(dnstype_map.keys()):
            if allowed(d):
                dnstype_map.pop(d, None)

    # ===== 父域覆盖子域：避免冗余 =====
    removed_by_parent = 0
    if ENABLE_PARENT_COLLAPSE and block_domains:
        # 为了保守：仅在同一 registrable 域名范围内做“父域覆盖子域”
        # 比如：a.b.example.co.uk 与 example.co.uk（同一注册域）
        # 避免跨注册域误合并
        by_reg = {}
        for d in block_domains:
            rd = _registrable_domain(d)
            by_reg.setdefault(rd, []).append(d)

        new_blocks = set()
        for rd, members in by_reg.items():
            # 短的（父域）排前
            members_sorted = sorted(members, key=lambda x: (len(_split_labels(x)), x))
            kept = []
            for d in members_sorted:
                if not any(_is_subdomain_of(d, p) for p in kept):
                    kept.append(d)
            new_blocks.update(kept)
            removed_by_parent += (len(members_sorted) - len(kept))

        block_domains = new_blocks

    # ===== 构造输出 =====
    block_rules = [f"||{d}^" for d in sorted(block_domains)]
    for d in sorted(dnsrewrite_map.keys()):
        for v in sorted(dnsrewrite_map[d]):
            block_rules.append(f"||{d}^$dnsrewrite={v}")
    for d in sorted(dnstype_map.keys()):
        for v in sorted(dnstype_map[d]):
            block_rules.append(f"||{d}^$dnstype={v}")

    domains = sorted(block_domains | set(dnsrewrite_map.keys()) | set(dnstype_map.keys()))

    total_after = len(block_rules)
    stats = {
        "total_before": total_before,
        "total_after": total_after,
        "dedup_removed": max(total_before - total_after, 0),
        "ignored": count_ignored,
        "hosts": count_hosts,
        "plain": count_plain,
        "dnsrewrite": count_dnsrewrite,
        "dnstype": count_dnstype,
        "removed_by_parent": removed_by_parent,
        "allow_count": len(allow_domains),
        "block_domains_count": len(block_domains)
    }
    # 返回第二项 raw_rules 为空（AGH 不需要浏览器层规则）
    return block_rules, [], domains, stats

# ========= 写出 =========
def write_outputs(block_rules, raw_rules_unused, domains, sources):
    with open(os.path.join(OUT_DIR,"merged_adblock.txt"),"w",encoding="utf-8") as f:
        f.write(header("Unified Adblock list for AdGuard Home (DNS-only)", sources))
        for r in block_rules:
            f.write(r+"\n")

    with open(os.path.join(OUT_DIR,"merged_hosts.txt"),"w",encoding="utf-8") as f:
        f.write("# 0.0.0.0 hosts merged (AGH-compatible)\n")
        for d in domains:
            f.write(f"0.0.0.0 {d}\n")

    with open(os.path.join(OUT_DIR,"merged_domains.txt"),"w",encoding="utf-8") as f:
        for d in domains:
            f.write(d+"\n")

# ========= 主流程 =========
def main():
    if not os.path.exists(SRC_FILE):
        print("sources.txt not found.", file=sys.stderr)
        sys.exit(1)

    # 读取源
    sources = []
    with open(SRC_FILE,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u and not u.startswith("#"):
                sources.append(u)

    if not sources:
        print("sources.txt is empty.", file=sys.stderr)
        sys.exit(1)

    # 拉取
    lines = []
    for url in sources:
        try:
            txt = fetch(url)
            lines.extend(txt.splitlines())
            print("OK:", url)
        except Exception as e:
            print("FAIL:", url, e)

    # 规范化 + 去重 + 冲突解决
    block_rules, _, domains, stats = normalize_and_dedupe(lines, keep_idna=KEEP_IDNA)

    # 写出
    write_outputs(block_rules, [], domains, sources)

    # 校验 + 统计
    for name in ("merged_adblock.txt","merged_hosts.txt","merged_domains.txt"):
        p = os.path.join(OUT_DIR, name)
        with open(p, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()[:16]
        print(f"Wrote {p}  sha256[:16]={sha}")

    print("\n=== Stats ===")
    print(f"总输入行: {stats['total_before']}")
    print(f"有效写出: {stats['total_after']}（AGH 识别规则数）")
    print(f"丢弃/忽略: {stats['ignored']}（注释/外观/浏览器层等）")
    print(f"hosts 行: {stats['hosts']}  纯域规则: {stats['plain']}  dnsrewrite: {stats['dnsrewrite']}  dnstype: {stats['dnstype']}")
    print(f"白名单域数: {stats['allow_count']}")
    print(f"块域数(父域折叠后): {stats['block_domains_count']}  子域被父域覆盖去除: {stats['removed_by_parent']}")
    if stats["total_before"] > 0:
        pct = (stats["total_before"] - stats["total_after"]) / stats["total_before"] * 100
    else:
        pct = 0.0
    print(f"总体去重率: {pct:.2f}%")

if __name__ == "__main__":
    main()
