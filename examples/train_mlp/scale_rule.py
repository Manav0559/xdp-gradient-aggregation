"""Reference for NetSum's per-chunk shared exponent (wire v3), shared by the
Python client, the quantization study and the tests.

A chunk's values travel as round(x * 2^e) in int32. Every worker must use the
same e for a (round, chunk); they agree without extra messages because every
worker receives the same summed result each round. The rule is integer-only
so C and Python can never disagree:

  next_exponent(prev_sum_ints, prev_e):
    m = max |prev_sum_ints|
    m == 0          -> prev_e + EMPTY_STEP          (sum underflowed: zoom in)
    otherwise       -> prev_e + (30 - HEADROOM_BITS - bitlen(m)), clamped 0..63
  after an OVERFLOW result -> prev_e - OVERFLOW_STEP

So the previous sum lands near 2^(30 - HEADROOM_BITS): a sum may grow
2^HEADROOM_BITS times between rounds before it overflows."""
import math

INT32_MAX = 2**31 - 1
INT32_MIN = -2**31
E_MIN, E_MAX = 0, 63
HEADROOM_BITS = 4
EMPTY_STEP = 8
OVERFLOW_STEP = 8
Q16 = 16


def clamp_e(e):
    return max(E_MIN, min(E_MAX, e))


def next_exponent(prev_sum_ints, prev_e, overflowed=False):
    if overflowed:
        return clamp_e(prev_e - OVERFLOW_STEP)
    m = max((abs(v) for v in prev_sum_ints), default=0)
    if m == 0:
        return clamp_e(prev_e + EMPTY_STEP)
    return clamp_e(prev_e + (30 - HEADROOM_BITS - m.bit_length()))


def quantize(x, e):
    """round(x * 2^e) half away from zero; returns (int32, saturated?)."""
    if x != x:
        return 0, False
    s = math.ldexp(x, e)
    if s >= INT32_MAX:
        return INT32_MAX, True
    if s <= INT32_MIN:
        return INT32_MIN, True
    return (int(s + 0.5) if s >= 0 else -int(-s + 0.5)), False


def dequantize(v, e):
    return math.ldexp(v, -e)
