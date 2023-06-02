# Extended Euclidean algorithm: returns g, x, y such that
#    a*x + b*y = g = gcd(a, b)
def egcd(a, b):
  x0, x1, y0, y1 = 0, 1, 1, 0
  while a != 0:
    (q, a), b = divmod(b, a), a
    x0, x1, y0, y1 = x1, x0 - q * x1, y1, y0 - q * y1
  return b, x0, y0

# Computes a^{-1} mod N
def modinv(a, N):
  _, a_inv, _ = egcd(a, N)
  return a_inv % N

# Compute a^b mod N
def power(a, b, N):
  val = 1
  while b > 0:
    if (b & 1) > 0:
      val = (val * a) % N
    a = (a * a) % N
    b >>= 1
  return val
