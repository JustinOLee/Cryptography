from bleichenbacher import Bleichenbacher
from util import power, modinv

import os
import secrets

import time

class BasicRSA:
  # Set up an RSA modulus with prime factors p, q and messages of size
  # msg_bytes
  def __init__(self, p, q, msg_bytes):
    self.p = p
    self.q = q

    self.N = self.p * self.q
    self.phiN = (self.p - 1) * (self.q - 1)
    self.e = 3
    self.d = modinv(self.e, self.phiN)

    k = self.N - 1
    self.N_bytes = 0
    while k > 0:
      k >>= 1
      self.N_bytes += 1
    self.N_bytes = (self.N_bytes + 7) // 8

    self.msg_bytes = msg_bytes
    self.padding_bytes = self.N_bytes - self.msg_bytes - 3

    self.oracle_calls = 0

  def get_public_key(self):
    return self.N, self.e

  # PKCS#1 encryption
  def encrypt(self, m):
    # Apply PKCS#1 padding to the message (with custom header 00 04)
    pad = [secrets.choice(range(1, 256)) for i in range(self.padding_bytes)]
    padded_msg = b'\x00\x04' + bytes(pad) + b'\x00' + (m).to_bytes(self.msg_bytes, 'big')
    val = int.from_bytes(padded_msg, byteorder = 'big')

    # Compute c = m^e mod N using repeated squaring
    ctxt = power(val, self.e, self.N)

    return ctxt

  # Check that mesage starts with 00 04
  def check_pad(self, m):
    m_bytes = (m).to_bytes(self.N_bytes, 'big')
    if m_bytes[0] != 0 or m_bytes[1] != 4:
      return False

    return True

  # Strips away the padding
  def unpad(self, padded_msg):
    msg_bytes = (padded_msg).to_bytes(self.N_bytes, 'big')
    return int.from_bytes(msg_bytes[3 + self.padding_bytes:], byteorder = 'big')

  # PKCS#1 decryption
  def decrypt(self, ctxt):
    val = power(ctxt, self.d, self.N)
    if not self.check_pad(val):
      return None

    return self.unpad(val)

  # Checks if ctxt is an encryption of a PKCS#1-padded message
  # (for simplicity, we say a message is properly padded if its leading
  #  first two bytes is 00 04 -- as computed by check_pad)
  def padding_oracle(self, ctxt):
    self.oracle_calls += 1
    return self.decrypt(ctxt) is not None

# 64-bit primes for testing purposes
P = 13382524637124739259
Q = 16561004363178600341

start_time = time.time()

# Construct the RSA instance for encrypting 8-byte messages
msg_bytes = 8
rsa = BasicRSA(P, Q, msg_bytes)
N, e = rsa.get_public_key()

# Sample a random secret and encrypt it using RSA with PKCS#1 padding
secret = os.urandom(msg_bytes)
print('Encrypting key', secret.hex())
ctxt = rsa.encrypt(int.from_bytes(secret, byteorder = 'big'))

# Invoke Bleichenbacher's padding oracle attack on the ciphertext
padded_msg = Bleichenbacher(N, e).decrypt(ctxt, rsa.padding_oracle)
msg = (rsa.unpad(padded_msg)).to_bytes(msg_bytes, byteorder = 'big')
print('Recovered key ', msg.hex())

print('Number of oracle calls made:', rsa.oracle_calls)
print("--- %s seconds ---" % (time.time() - start_time))
