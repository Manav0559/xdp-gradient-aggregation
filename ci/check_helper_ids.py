"""Checks every BPF helper ID, map-type constant and XDP action vendored in
xdp_agg/bpf_compat.h against a real <linux/bpf.h>, so the compat header can
never silently call the wrong helper.

Usage: check_helper_ids.py <path to linux/bpf.h> <path to bpf_compat.h>
"""
import re
import sys


def helper_ids(uapi):
    """Helper name -> ID from the __BPF_FUNC_MAPPER list. Newer headers give
    explicit IDs (FN(map_lookup_elem, 1, ##ctx)); older ones are positional."""
    start = uapi.index("_BPF_FUNC_MAPPER(FN")
    body = uapi[start:uapi.index("/* */", start) if "/* */" in uapi[start:] else start + 40000]
    ids, pos = {}, 0
    for m in re.finditer(r"FN\((\w+)(?:\s*,\s*(\d+))?", body):
        if m.group(1) == "FN":
            continue
        ids[m.group(1)] = int(m.group(2)) if m.group(2) else pos
        pos += 1
    return ids


def enum_values(uapi, enum_name):
    m = re.search(r"enum " + enum_name + r"\s*\{(.*?)\};", uapi, re.S)
    vals, nxt = {}, 0
    for item in re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S).split(","):
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        name, _, val = item.partition("=")
        name = name.strip()
        if val.strip():
            try:
                nxt = int(val.strip(), 0)
            except ValueError:
                continue
        vals[name] = nxt
        nxt += 1
    return vals


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    uapi, compat = open(sys.argv[1]).read(), open(sys.argv[2]).read()
    bad = 0
    ids = helper_ids(uapi)
    for name, num in re.findall(r"\(\*bpf_(\w+)\)\([^;]*=\s*\(void \*\)(\d+);", compat):
        real = ids.get(name)
        status = "ok" if real == int(num) else "MISMATCH"
        bad += status != "ok"
        print(f"helper bpf_{name}: compat {num}, linux/bpf.h {real} -> {status}")
    maps = enum_values(uapi, "bpf_map_type")
    for name, num in re.findall(r"#define (BPF_MAP_TYPE_\w+) (\d+)", compat):
        status = "ok" if maps.get(name) == int(num) else "MISMATCH"
        bad += status != "ok"
        print(f"{name}: compat {num}, linux/bpf.h {maps.get(name)} -> {status}")
    actions = enum_values(uapi, "xdp_action")
    for name in ("XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"):
        want = ["XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"].index(name)
        status = "ok" if actions.get(name) == want else "MISMATCH"
        bad += status != "ok"
        print(f"{name}: compat {want}, linux/bpf.h {actions.get(name)} -> {status}")
    for flag in ("BPF_ANY", "BPF_NOEXIST", "BPF_EXIST"):
        m = re.search(r"#define " + flag + r" (\d+)", compat)
        real = re.search(r"\b" + flag + r"\s*=\s*(\d+)", uapi) or re.search(r"#define " + flag + r"\s+(\d+)", uapi)
        status = "ok" if m and real and m.group(1) == real.group(1) else "MISMATCH"
        bad += status != "ok"
        print(f"{flag}: compat {m and m.group(1)}, linux/bpf.h {real and real.group(1)} -> {status}")
    print("all vendored IDs match" if not bad else f"{bad} mismatch(es)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
