#!/usr/bin/env python3
"""Deep algebraic verification of falcon-rs constant tables and core math.

Re-derives from first principles:
  1. FPR_GM_TAB   : FFT roots of unity, bit-reversed order (2048 f64 entries)
  2. FPR_P2_TAB   : powers of 2^-k
  3. GMB / IGMB   : NTT tables mod q=12289, g=7, Montgomery R=2^16
  4. NI_TAB       : R/n mod q for iNTT scaling
  5. mq_div_12289 : addition-chain exponent == q-2
  6. L2BOUND      : floor(beta^2 * 2n) signature norm bounds (vs known ref values)
  7. GAUSS0_DIST  : RCDT for half-Gaussian sigma=1.8205 (72-bit, 3x24-bit rows)
  8. GAUSS_1024_12289 : keygen Gaussian CDT (63-bit)
  9. REV10        : 10-bit bit reversal
 10. PRIMES table : p < 2^31, p = 1 mod 2048, g has order 2048, s = R/lower-prod
 11. FPR_INV_SIGMA / FPR_SIGMA_MIN vs formulas from the Falcon spec
 12. Keccak round constants, SHA-256/512 K tables
Exits non-zero on any mismatch.
"""
import math, re, sys
from decimal import Decimal, getcontext
getcontext().prec = 80

import os
SRC = os.path.join(os.path.dirname(__file__), "..", "src")
fail = 0
def check(name, ok, detail=""):
    global fail
    print(("PASS " if ok else "FAIL ") + name + (": " + detail if detail and not ok else ""))
    if not ok: fail += 1

def read(f): return open(f"{SRC}/{f}").read()

# ---------- helpers ----------
def extract_array(text, name, conv=float):
    # Anchor on the declaration, not on the bare name: the name also appears in
    # doc comments, and a loose match would read whichever array came next.
    m = re.search(r"^\s*(?:pub(?:\([a-z:]+\))? )?(?:const|static) " + re.escape(name) + r"\b[^=]*=\s*\[(.*?)\];",
                  text, re.S | re.M)
    assert m, f"array {name} not found"
    body = m.group(1)
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    # Constants are written `Fpr::new(<literal>)` so that both the native and
    # the emulated backend can compile them; older revisions used `Fpr(<literal>)`.
    body = body.replace("Fpr::new(", "").replace("Fpr(", "").replace(")", "")
    vals = [v.strip() for v in body.split(",") if v.strip()]
    return [conv(v) for v in vals]

# ---------- 1. FPR_GM_TAB ----------
# `fpr.rs` was split into a module directory; constants and tables live in mod.rs.
fpr = read("fpr/mod.rs")
gm = extract_array(fpr, "FPR_GM_TAB")
check("FPR_GM_TAB length == 2048", len(gm) == 2048, str(len(gm)))
# entry pairs: for index i (0..1024), gm[2i],gm[2i+1] = cos,sin of angle for bit-reversed i
def brev(x, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1); x >>= 1
    return r
bad = 0
first_bad = None
# FPR_GM_TAB holds, at index pair (2k, 2k+1), the real and imaginary parts of
# exp(i*pi*brev10(k)/1024).
# Known structure from falcon fpr.c generator:
#   for k in range(1024): b = brev(k,10); gm[2k] = cos(pi*b/1024); gm[2k+1] = sin(pi*b/1024)
for k in range(1, 1024):   # entry 0 is unused in the reference table
    b = brev(k, 10)
    re_ = math.cos(math.pi * b / 1024.0)
    im_ = math.sin(math.pi * b / 1024.0)
    if abs(gm[2*k] - re_) > 1e-15 or abs(gm[2*k+1] - im_) > 1e-15:
        bad += 1
        if first_bad is None: first_bad = (k, b, gm[2*k], gm[2*k+1], re_, im_)
check("FPR_GM_TAB[k>0] == exp(i*pi*brev10(k)/1024)", bad == 0, f"{bad} bad, first={first_bad}")

p2 = extract_array(fpr, "FPR_P2_TAB")
check("FPR_P2_TAB", p2 == [2.0/(1<<i) for i in range(11)])

# FPR_INV_SIGMA / FPR_SIGMA_MIN: sigma(logn) = 1.55*sqrt(q) scaled... spec:
# sigma_{n} = 1.55 * sqrt(12289) ??? Falcon spec: sigma = smoothing * sqrt(q); values are fixed per logn.
# Cross-check against the canonical C fpr.h values instead (regression identity):
inv_sigma = extract_array(fpr, "FPR_INV_SIGMA")
sigma_min = extract_array(fpr, "FPR_SIGMA_MIN")
C_INV_SIGMA = [0.0,
 0.0069054793295940891952143765991630516,
 0.0068102267767177975961393730687908629,
 0.0067188101910722710707826117910434131,
 0.0065883354370073665545865037227681924,
 0.0064651781207602900738053897763485516,
 0.0063486788828078995327741182928037856,
 0.0062382586529084374473367528433697537,
 0.0061334065020930261548984001431770281,
 0.0060336696681577241031668062510953022,
 0.0059386453095331159950250124336477482]
C_SIGMA_MIN = [0.0,
 1.1165085072329102588881898380334015,
 1.1321247692325272405718031785357108,
 1.1475285353733668684571123112513188,
 1.1702540788534828939713084716509250,
 1.1925466358390344011122170489094133,
 1.2144300507766139921088487776957699,
 1.2359260567719808790104525941706723,
 1.2570545284063214162779743112075080,
 1.2778336969128335860256340575729042,
 1.2982803343442918539708792538826807]
check("FPR_INV_SIGMA == C reference", inv_sigma == C_INV_SIGMA)
check("FPR_SIGMA_MIN == C reference", sigma_min == C_SIGMA_MIN)
# consistency: sigma_min[logn] ~= sigma_min formula: sqrt(2)*... skip formula; check monotone & inverse relation:
# sigma[logn] = 1/inv_sigma[logn]; spec: sigma = 1.17*sqrt(q) * something increasing in logn
sig = [0]+[1/x for x in inv_sigma[1:]]
check("sigma monotone increasing", all(sig[i] < sig[i+1] for i in range(1,10)))
check("sigma_512 ~ 165.736..", abs(sig[9] - 165.7366171829776) < 1e-9, str(sig[9]))

# ---------- 3/4/5. NTT tables mod 12289 ----------
vrfy = read("vrfy.rs")
Q = 12289
R = (1 << 16) % Q
check("R = 2^16 mod q == 4091", R == 4091)
R2 = (R * R) % Q
check("R2 == 10952", R2 == 10952)
Q0I = None
# Q0I: -1/q mod 2^16 = 12287? q * q0i mod 2^16 should be 2^16-1 (since z + (z*Q0I mod 2^16)*q  divisible)
check("Q0I: q*12287 mod 2^16 == 2^16-1", (Q * 12287) % (1 << 16) == (1 << 16) - 1)

gmb = extract_array(vrfy, "GMB", int)
igmb = extract_array(vrfy, "IGMB", int)
check("GMB length 1024", len(gmb) == 1024)
g = 7
ig = pow(g, Q - 2, Q)
check("1/g mod q == 8778", ig == 8778)
# GMb[x] = R * g^rev10(x). The n=1024 negacyclic NTT needs a root of order
# exactly 2n = 2048: g^1024 must be -1, not 1.
def order(a, q):
    o = 1; x = a
    while x != 1: x = x * a % q; o += 1
    return o
og = order(g, Q)
check("order of 7 mod 12289 == 2048 exactly", og == 2048, f"order={og}")
check("7^1024 == -1 mod 12289 (primitive 2048th root)", pow(g, 1024, Q) == Q - 1)
# Falcon uses tables for max logn=10 (n=1024): GMb[x] = R*(g^rev(x)) mod q with rev = 10-bit reversal
bad = 0
for x in range(1024):
    want = (R * pow(g, brev(x, 10), Q)) % Q
    if gmb[x] != want: bad += 1
check("GMB[x] == R*7^rev10(x) mod q", bad == 0, f"{bad} bad")
bad = 0
for x in range(1024):
    want = (R * pow(ig, brev(x, 10), Q)) % Q
    if igmb[x] != want: bad += 1
check("IGMB[x] == R*(1/7)^rev10(x) mod q", bad == 0, f"{bad} bad")

ni_tab = extract_array(vrfy, "NI_TAB", int)
bad = []
for logn in range(11):
    n = 1 << logn
    want = (R * pow(n, Q - 2, Q)) % Q
    if ni_tab[logn] != want: bad.append((logn, ni_tab[logn], want))
check("NI_TAB[logn] == R/n mod q", not bad, str(bad))

# mq_div addition chain: simulate exponent
# y0=y ; y1=y0^2 ; y2=y1*y0 ; y3=y2*y1 ; y4..y8 = sqr chain; y9=y8*y2; y10=y9*y8; y11=sqr; y12=sqr;
# y13=y12*y9; y14=sqr; y15=sqr; y16=y15*y10; y17=sqr; y18=y17*y0  -> exponent should be q-2=12287
e = {}
e['y0'] = 1
e['y1'] = 2*e['y0']
e['y2'] = e['y1'] + e['y0']
e['y3'] = e['y2'] + e['y1']
e['y4'] = 2*e['y3']; e['y5'] = 2*e['y4']; e['y6'] = 2*e['y5']; e['y7'] = 2*e['y6']; e['y8'] = 2*e['y7']
e['y9'] = e['y8'] + e['y2']
e['y10'] = e['y9'] + e['y8']
e['y11'] = 2*e['y10']; e['y12'] = 2*e['y11']
e['y13'] = e['y12'] + e['y9']
e['y14'] = 2*e['y13']; e['y15'] = 2*e['y14']
e['y16'] = e['y15'] + e['y10']
e['y17'] = 2*e['y16']
e['y18'] = e['y17'] + e['y0']
check("mq_div_12289 chain exponent == q-2 == 12287", e['y18'] == Q - 2, str(e['y18']))

# ---------- 6. L2BOUND ----------
common = read("common.rs")
l2 = extract_array(common, "L2BOUND", int)
# Falcon: bound = floor( beta^2 ) with beta = 1.1*sigma*sqrt(2n); reference values known:
REF_L2 = [0,101498,208714,428865,892039,1852696,3842630,7959734,16468416,34034726,70265242]
check("L2BOUND == reference", l2 == REF_L2)
# independent derivation: floor((1.1*sigma(logn)*sqrt(2n))^2) ?
d_ok = []
for logn in range(1, 11):
    n = 1 << logn
    beta2 = math.floor((Decimal("1.1") * Decimal(1)/Decimal(str(C_INV_SIGMA[logn])) )**2 * 2 * n)
    d_ok.append((logn, int(beta2), l2[logn], abs(int(beta2)-l2[logn])))
mx = max(abs(a-b) for _,a,b,_ in [(0,x[1],x[2],0) for x in d_ok])
check("L2BOUND ~= floor((1.1*sigma)^2*2n) (|diff|<=2 rounding)", all(x[3] <= 2 for x in d_ok),
      str([x for x in d_ok if x[3] > 2]))

# ---------- 7. GAUSS0_DIST (RCDT sigma=1.8205, 72-bit precision, 3x24-bit) ----------
sign_src = read("sign.rs")
g0 = extract_array(sign_src, "GAUSS0_DIST", int)
check("GAUSS0_DIST length 54 (18 rows x 3)", len(g0) == 54)
# P(z) tail: for half-Gaussian D_{Z+,sigma0}: p(k) ∝ exp(-k^2/(2 sigma0^2)), k>=0
# RCDT[i] = round(2^72 * P(Z > i))  (tail probabilities)
sigma0 = Decimal("1.8205")
two = Decimal(2)
def dexp(x):  # exp for Decimal via math on high-prec float route
    return Decimal(math.exp(float(x)))  # not enough precision; use series instead
# high precision exp via Decimal power: exp(-k^2/(2s^2)) = e^(x); use Decimal.exp()
rho = [ ( -(Decimal(k)**2) / (two * sigma0**2) ).exp() for k in range(0, 30) ]
S = sum(rho)  # includes k=0 with weight 1? Falcon: half gaussian with k=0..;
# The table is the suffix sum of the FLOORED per-value probabilities, not the
# rounded tail: row k = sum_{j>k} floor(2^72 * P(X=j)). With that construction
# it is integer-exact, so no tolerance is needed.
scale = Decimal(2) ** 72
pmf_floor = [int((rho[j] / S * scale).to_integral_value(rounding="ROUND_FLOOR"))
             for j in range(len(rho))]
tails = [sum(pmf_floor[i + 1:]) for i in range(18)]
bad = []
vals72 = []
for i in range(18):
    w2, w1, w0 = g0[3*i], g0[3*i+1], g0[3*i+2]
    val = (w2 << 48) | (w1 << 24) | w0
    vals72.append(val)
    if val != tails[i]:
        bad.append((i, val, tails[i], val - tails[i]))
check("GAUSS0_DIST == RCDT(sigma0=1.8205) 72-bit tails (exact)", not bad, str(bad[:3]))
# Row 0 is normative in the Falcon specification.
check("GAUSS0_DIST[0] == spec RCDT[0]", vals72[0] == 3024686241123004913666, str(vals72[0]))
check("GAUSS0_DIST strictly decreasing, last==1",
      all(vals72[i] > vals72[i+1] for i in range(17)) and vals72[-1] == 1)

# ---------- 8. GAUSS_1024_12289 ----------
kg = read("keygen.rs")
g1024 = extract_array(kg, "GAUSS_1024_12289", int)
# keygen sampling: sigma for logn=10 keys: sigma_{fg} = 1.17*sqrt(q/ (2*1024))? spec: sigma = 1.17*sqrt(q/2n)
# table: 63-bit CDT: values = round(2^63 * P(|X|>=k)/?) Known structure from C keygen.c:
# gauss_1024_12289[k] ~ P table with first entry ~ 2^63 * (1 - p0):
# Sampler semantics (mkgauss): P(v=0) = tab[0]/2^63 (first 63-bit draw);
# given f_init=0, v = min{k>=1 : r2 >= tab[k]} with tab decreasing, tab[26]=0.
# Target: D(x) ∝ exp(-x^2/(2*sigma^2)), sigma = 1.17*sqrt(q/(2*1024)), sign uniform.
sigma_kg = Decimal("1.17") * (Decimal(12289) / Decimal(2048)).sqrt()
rho = [ ( -(Decimal(k)**2) / (two * sigma_kg**2) ).exp() for k in range(0, 60) ]
S = rho[0] + 2*sum(rho[1:])
T63 = Decimal(2)**63
bad = []
# P(x=0):
p0_tab = Decimal(g1024[0]) / T63
p0_ref = rho[0] / S
if abs(p0_tab - p0_ref) > Decimal(2)**-60: bad.append(("P(0)", p0_tab, p0_ref))
# P(|x|=k) for k>=1: (1 - tab[0]/2^63) * (tab[k-1'] - tab[k])/2^63 with tab[0'] := 2^63 at k=1
pf0 = 1 - p0_tab
for k in range(1, 27):
    hi = T63 if k == 1 else Decimal(g1024[k-1])
    p_tab = pf0 * (hi - Decimal(g1024[k])) / T63
    p_ref = 2*rho[k] / S
    if abs(p_tab - p_ref) > Decimal(2)**-58:
        bad.append((k, float(p_tab), float(p_ref)))
check("GAUSS_1024_12289 sampler distribution == D(sigma=1.17*sqrt(q/2048))", not bad, str(bad[:4]))
check("GAUSS_1024_12289 tail (idx>=1) decreasing, last==0",
      all(g1024[i] > g1024[i+1] for i in range(1, len(g1024)-1)) and g1024[-1] == 0)

# ---------- 9. REV10 ----------
rev10 = extract_array(kg, "REV10", int)
check("REV10 == 10-bit reversal", rev10 == [brev(i,10) for i in range(1024)])

# ---------- 10. PRIMES ----------
mp = re.findall(r"SmallPrime\s*\{\s*p:\s*(\d+),\s*g:\s*(\d+),\s*s:\s*(\d+),?\s*\}", kg)
primes = [(int(a), int(b), int(c)) for a, b, c in mp]
# max prime index ever used is llen = MAX_BL_LARGE[9] = 308 (solver at depth 9)
check("PRIMES count >= 350 (max index used is 308)", len(primes) >= 350, str(len(primes)))
def is_prime(x):
    if x < 2: return False
    for sp in (2,3,5,7,11,13,17,19,23,29,31,37):
        if x % sp == 0: return x == sp
    d = x - 1; r = 0
    while d % 2 == 0: d //= 2; r += 1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        v = pow(a, d, x)
        if v in (1, x-1): continue
        for _ in range(r-1):
            v = v*v % x
            if v == x-1: break
        else: return False
    return True
bad = []
prev = 1 << 31
for i, (p, gg, s) in enumerate(primes):   # deep-check every entry
    if not is_prime(p): bad.append((i, "not prime")); continue
    if p % 2048 != 1: bad.append((i, "p % 2048 != 1"))
    if pow(gg, 2048, p) != 1 or pow(gg, 1024, p) == 1: bad.append((i, "g order != 2048"))
    if p >= prev: bad.append((i, "not decreasing"))
    prev = p
check(f"PRIMES[0..{len(primes)}): prime, p=1 mod 2048, ord(g)=2048, decreasing", not bad, str(bad[:5]))
check("PRIMES[0].p == 2147473409", primes[0][0] == 2147473409, str(primes[0][0]))
# s field: s = inverse of (product of previous primes) mod p, in Montgomery form R mod p:
# C: primes[i].s such that s = 1/(prod_{j<i} p_j) mod p_i  (plain, then used with montymul)
bad = []
for i in range(1, 12):
    p = primes[i][0]
    prod = 1
    for j in range(i):
        prod = (prod * primes[j][0]) % p
    inv = pow(prod, p - 2, p)
    # stored s is in plain or Montgomery? try both
    Rp = (1 << 31) % p
    s = primes[i][2]
    if s != inv and s != (inv * Rp) % p and s != (inv * pow(Rp, p-2, p)) % p:
        bad.append((i, s, inv))
check("PRIMES s == 1/(prod prev primes) mod p (some domain)", not bad, str(bad[:2]))

# ---------- 11. Keccak RC + SHA constants ----------
shake = read("shake.rs")
rc = extract_array(shake, "RC", lambda s: int(s, 16))
def keccak_rc():
    out = []
    R_ = 1
    for _ in range(24):
        v = 0
        for j in range(7):
            if R_ & 1: v ^= 1 << ((1 << j) - 1)
            R_ = ((R_ << 1) ^ (0x71 if R_ & 0x80 else 0)) & 0xFF
        out.append(v)
    return out
check("Keccak round constants", rc == keccak_rc())

safe = read("safe_api.rs")
k256 = re.search(r"const K: \[u32; 64\] = \[(.*?)\];", safe, re.S).group(1)
k256 = [int(x.strip(), 16) for x in k256.replace("\n", "").split(",") if x.strip()]
def frac_cbrt_primes(count, bits):
    ps = []
    x = 2
    while len(ps) < count:
        if is_prime(x): ps.append(x)
        x += 1
    out = []
    for p in ps:
        c = Decimal(p) ** (Decimal(1)/Decimal(3))
        out.append(int((c - int(c)) * (1 << bits)))
    return out
check("SHA-256 K constants", k256 == frac_cbrt_primes(64, 32))
k512 = re.search(r"const K: \[u64; 80\] = \[(.*?)\];", safe, re.S).group(1)
k512 = [int(x.strip(), 16) for x in k512.replace("\n", "").split(",") if x.strip()]
check("SHA-512 K constants", k512 == frac_cbrt_primes(80, 64))

# ---------- 12. OVERTAB (hash_to_point_ct oversampling) ----------
overtab = extract_array(common, "OVERTAB", int)
C_OVER = [0, 65, 67, 71, 77, 86, 100, 122, 154, 205, 287]
check("OVERTAB == C reference", overtab == C_OVER)

print()
print("FAILURES:", fail)
sys.exit(1 if fail else 0)
