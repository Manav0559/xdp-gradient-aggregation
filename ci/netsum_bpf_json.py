"""Readers for `bpftool -j map dump` output of NetSum's maps. bpftool emits
each entry with raw little-endian hex bytes and, when the object has BTF, a
decoded "formatted" object; both are handled. Counter names come from
protocol/netsum_stats.h so there is one list of names."""
import json
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLOT_STATES = {0: "empty", 1: "accumulating", 2: "completed", 3: "flushed"}


def load(path):
    with open(path) as f:
        return json.load(f)


def _le(hex_bytes):
    return sum(int(b, 16) << (8 * i) for i, b in enumerate(hex_bytes))


def stat_names():
    text = open(os.path.join(REPO, "protocol", "netsum_stats.h")).read()
    body = text[text.index("enum netsum_stat {"):text.index("NS_STAT__COUNT")]
    names = []
    for line in body.splitlines()[1:]:
        line = re.sub(r"/\*.*?\*/", "", line)
        for tok in line.split(","):
            tok = tok.strip().split("=")[0].strip()
            if tok.startswith("NS_"):
                names.append(tok[3:].lower())
    return names


def stats(path):
    """{name: sum over CPUs} from a dump of the PERCPU_ARRAY `stats` map."""
    names = stat_names()
    out = {}
    for e in load(path):
        f = e.get("formatted", e)
        key = f["key"] if isinstance(f["key"], int) else _le(f["key"])
        vals = f.get("values", [])
        total = 0
        for v in vals:
            x = v["value"]
            total += x if isinstance(x, int) else _le(x)
        if key < len(names):
            out[names[key]] = total
    return out


def slots(path):
    """[(job_id, round, chunk_id, state_name, contributors)] from a slot_map dump."""
    out = []
    for e in load(path):
        f = e.get("formatted", e)
        k, v = f["key"], f["value"]
        if isinstance(k, dict):
            key = (int(k["job_id"]), int(k["round"]), int(k["chunk_id"]))
        else:
            key = (_le(k[0:4]), _le(k[4:8]), _le(k[8:12]))
        if isinstance(v, dict):
            state, contributors = int(v["state"]), int(v["contributors"])
        else:
            state, contributors = int(v[4], 16), _le(v[12:14])
        out.append(key + (SLOT_STATES.get(state, str(state)), contributors))
    return out
