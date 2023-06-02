import math
import util

class Bleichenbacher:
  def __init__(self, N, e):
    self.N = N
    self.e = e

  def decrypt(self, ctxt, oracle):
    # k setup
    k = (self.N.bit_length() + 7) // 8
    
    # B, M, i, s_1 setup
    B = 2 ** (8 * (k - 2))
    M = [[(4*B), (5*B) - 1]]
    s = (self.N + (5*B) - 1) // (5*B)
    check = (ctxt * (util.power(s, self.e, self.N))) % self.N
    while not oracle(check):
      s += 1
      check = (ctxt * (util.power(s, self.e, self.N))) % self.N
    
    
    # a is res, default to -1
    a = -1

    while a == -1:
      if len(M) == 1:
        r = ((2*(M[0][1]*s - 4*B)) + self.N - 1) // self.N
        while True:
          # s starts at: (4B + rN) / b
          s = (((4*B) + (r*self.N)) + M[0][1] - 1) // M[0][1]
          check = (ctxt * (util.power(s, self.e, self.N))) % self.N
          found = oracle(check)
          # limit = (5B + rN ) / a
          limit = (((5*B) + (r*self.N)) + M[0][0] - 1) // M[0][0]
          while s < limit and not found:
            s += 1
            check = (ctxt * (util.power(s, self.e, self.N))) % self.N
            found = oracle(check)
          if found:
            break
          else:
            r += 1
      else:
        s += 1
        check = (ctxt * (util.power(s, self.e, self.N))) % self.N
        while not oracle(check):
          s += 1
          check = (ctxt * (util.power(s, self.e, self.N))) % self.N

      newset = []
      for interval in M:
        lower = (((interval[0] * s) - (5 * B) + 1) + self.N - 1 ) // self.N
        upper = (((interval[1] * s) - (4 * B)) + self.N - 1 ) // self.N

        for r in range(lower, upper + 1):
          cur = []
          cur.append(max(interval[0], (((4 * B) + (r * self.N)) + s - 1 ) // s))
          cur.append(min(interval[1], ((5 * B) - 1 + (r * self.N)) // s))

          if cur[0] <= cur[1]:
            newset.append(cur)
      
      M = newset
      
      if len(M) == 1 and M[0][0] == M[0][1]:
        a = M[0][0]

    return a
