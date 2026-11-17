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
2^HEADROOM_BITS times between rounds before it overflows.

With N workers each value is bounded by worker_limit(N) = INT32_MAX // N, so
no order of adding N values can overflow an int32 accumulator: overflow is
decided by each worker's own saturation, identically everywhere. A chunk
that overflows is retried in the same round at e - OVERFLOW_STEP under the
key chunk_id | attempt << RETRY_SHIFT (netsum_client.retry_chunk_id)."""
import math

INT32_MAX = 2**31 - 1
INT32_MIN = -2**31
E_MIN, E_MAX = 0, 63
HEADROOM_BITS = 4
EMPTY_STEP = 8
OVERFLOW_STEP = 8
MAX_ATTEMPTS = (E_MAX - E_MIN) // OVERFLOW_STEP + 2
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


def worker_limit(n_workers):
    return INT32_MAX // n_workers


def quantize(x, e, limit=None):
    """round(x * 2^e) half away from zero; returns (int32, saturated?).
    With `limit`, |value| is bounded by it instead of the int32 range."""
    if x != x:
        return 0, False
    s = math.ldexp(x, e)
    hi, lo = (INT32_MAX, INT32_MIN) if limit is None else (limit, -limit)
    if s >= hi:
        return hi, True
    if s <= lo:
        return lo, True
    q = int(s + 0.5) if s >= 0 else -int(-s + 0.5)
    if q > hi or q < lo:
        return (hi if q > 0 else lo), True
    return q, False


def dequantize(v, e):
    return math.ldexp(v, -e)
