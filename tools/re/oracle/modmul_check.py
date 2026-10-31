#!/usr/bin/env python3
"""BUG #53 stage check: the Barrett modmul pipeline inside the ORDER zp,
against the engine's staged-stop dumps (fips_modmul_kat stages)."""

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
k = 0x3830b344fc565fe6dac4077981e2ea5269f38c1a973d61aa20fc663cc74a6c5f
w4 = 0x528e86873cbdf34752427bccedb4a8b2c0a0f60dbf0fa61ce02c245772dbfdb1
mu = (1 << 512) // n

def limbs(v, cnt):
    return [f'{(v >> (64*i)) & 0xFFFFFFFFFFFFFFFF:016x}' for i in range(cnt)]

product = k * w4
qhat = product >> 255
mq = mu * qhat
q = mq >> 257
nq = n * q
r = product - nq
# conditional corrections
corr = 0
while r >= n:
    r -= n
    corr += 1

print('product (8 limbs):', limbs(product, 8))
print('q_hat   (5 limbs):', limbs(qhat, 5))
print('mu*qhat (10):     ', limbs(mq, 10))
print('q      (6 limbs):', limbs(q, 6))
print('n*q    (8 limbs):', limbs(nq, 8))
print('r = x - n*q      :', limbs(r, 4), f'(corr={corr})')
print('r mod n           :', limbs(r % n, 4))
print('TRUE out = k*w%n  :', limbs(k * w4 % n, 4))
print()
print('mu (5 limbs):     ', limbs(mu, 5))
print('n  (4 limbs):     ', limbs(n, 4))
