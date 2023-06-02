import pickle
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class PasswordManager:
  MAX_PASSWORD_LEN = 64

  def __init__(self, password, data = None, checksum = None):
    """Constructor for the password manager.
    
    Args:
      password (str) : master password for the manager
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty password
                              manager)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self.kvs = {}
    if data is None:
      salt = os.urandom(16)
    else:
      salt = bytes.fromhex(data[:32])
    self.salt = salt
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt,
                    iterations = 2000000)
    master = kdf.derive(bytes(password, 'ascii'))
    h_hmac = hmac.HMAC(master, hashes.SHA256())
    h_aes = hmac.HMAC(master, hashes.SHA256())
    h_iv = hmac.HMAC(master, hashes.SHA256())
    h_generate = hmac.HMAC(master, hashes.SHA256())
    
    # HMAC for key-derivation using the master password and distinct tags
    # Nonces (IVs) should also be random and unpredictable, so use HMAC as a PRF to generate them
    h_hmac.update(bytes("mac", 'ascii'))
    self.hmac_key = h_hmac.finalize()

    h_aes.update(bytes("aes", 'ascii'))
    self.aes_key = h_aes.finalize()

    h_iv.update(bytes("nonce", 'ascii'))
    self.iv_key = h_iv.finalize()

    h_generate.update(bytes("generate", 'ascii'))
    self.generate_key = h_generate.finalize()

    if data is not None:
      loaded_kvs = pickle.loads(bytes.fromhex(data[32:]))
      # verify checksum
      if checksum is not None:
        validate = hashes.Hash(hashes.SHA256())
        validate.update(bytes.fromhex(data))
        validate_checksum = validate.finalize()
        if validate_checksum.hex() != checksum:
          raise ValueError("Incorrect checksum.")

      # verify contents against master key by decrypyting each v
      try:
        aesgcm = AESGCM(self.aes_key)
        # An invalid aesgcm.decrypt should raise a InvalidTag exception as defined in the module
        for k, v in loaded_kvs.items():
          h_iv = hmac.HMAC(self.iv_key, hashes.SHA256())
          h_iv.update(k)
          random_iv = h_iv.finalize()
          aesgcm.decrypt(random_iv, v, None)
      except:
        raise ValueError("Invalid deserialization.")
      self.kvs = loaded_kvs

  def dump(self):
    """Computes a serialized representation of the password manager
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """

    ser_data = self.salt.hex() + pickle.dumps(self.kvs).hex()

    generate_checksum = hashes.Hash(hashes.SHA256())
    generate_checksum.update(bytes.fromhex(ser_data)) 
    checksum_bytes = generate_checksum.finalize()

    return ser_data, checksum_bytes.hex()

  def get(self, domain):
    """Fetches the password associated with a domain from the password
       manager.
    
    Args:
      domain (str) : the domain to fetch
    
    Returns: 
      password (str) : the password associated with the requested domain if
                       it exists and otherwise None
    """
    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h.update(bytes(domain, 'ascii'))
    hashed_domain = h.finalize()

    if hashed_domain in self.kvs:
      aesgcm = AESGCM(self.aes_key)
      h_iv = hmac.HMAC(self.iv_key, hashes.SHA256())
      h_iv.update(hashed_domain)
      random_iv = h_iv.finalize()

      dec_bytes = aesgcm.decrypt(random_iv, self.kvs[hashed_domain], None)

      unpadder = padding.PKCS7(self.MAX_PASSWORD_LEN * 8).unpadder()
      data = unpadder.update(dec_bytes)
      data += unpadder.finalize()

      return data.decode('ascii')

    return None

  def set(self, domain, password):
    """Associates a password with a domain and adds it to the password
       manager (or updates the associated password if the domain is already
       present in the password manager).
       
       Args:
         domain (str) : the domain to set
         password (str) : the password associated with the domain

       Returns:
         None

       Raises:
         ValueError : if password length exceeds the maximum
    """
    if len(password) > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    encoded_pw = bytes(password, 'ascii')

    padder = padding.PKCS7(self.MAX_PASSWORD_LEN * 8).padder()
    padded_pw = padder.update(encoded_pw)
    padded_pw += padder.finalize()
    
    h_hash = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h_hash.update(bytes(domain, 'ascii'))
    hashed_domain = h_hash.finalize()

    aesgcm = AESGCM(self.aes_key)
    h_iv = hmac.HMAC(self.iv_key, hashes.SHA256())
    h_iv.update(hashed_domain)
    random_iv = h_iv.finalize()

    encrypted_pw = aesgcm.encrypt(random_iv, padded_pw, None)

    self.kvs[hashed_domain] = encrypted_pw


  def remove(self, domain):
    """Removes the password for the requested domain from the password
       manager.
       
       Args:
         domain (str) : the domain to remove

       Returns:
         success (bool) : True if the domain was removed and False if the domain was
                          not found
    """

    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h.update(bytes(domain, 'ascii'))
    hashed_domain = h.finalize()

    if hashed_domain in self.kvs:
      del self.kvs[hashed_domain]
      return True

    return False

  def generate_new(self, domain, desired_len):
    """Generates a password for a particular domain. The password
       is a random string with characters drawn from [A-Za-z0-9].
       The password is automatically added to the password manager for
       the associated domain.
       
       Args:
         domain (str) : the domain to generate a password for
         desired_len (int) : length of the password to generate (in characters)

       Returns:
         password (str) : the generated password

       Raises:
         ValueError : if a password already exists for the provided domain
         ValueError : if the requested password length exceeds the maximum
    """
    encoded_domain = bytes(domain, 'ascii')
    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h.update(encoded_domain)
    hashed_domain = h.finalize()

    if hashed_domain in self.kvs:
      raise ValueError('Domain already in database')
    if desired_len > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    padder = padding.PKCS7(512).padder()
    padded_domain = padder.update(encoded_domain)
    padded_domain += padder.finalize()
    
    h_iv = hmac.HMAC(self.iv_key, hashes.SHA256())
    h_iv.update(padded_domain)
    random_iv = h_iv.finalize()[:16]

    cipher = Cipher(algorithms.AES(self.generate_key), modes.CBC(random_iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_domain) + encryptor.finalize()
    
    new_password = self.to_alphanum(ct[:desired_len]).decode('ascii')
    self.set(domain, new_password)

    return new_password

  def to_alphanum(self, b):
    bytes_ar = bytearray(b)
    for i in range(len(bytes_ar)):
      if bytes_ar[i] > 61:
        bytes_ar[i] %= 62

    for i in range(len(bytes_ar)):
      if bytes_ar[i] >= 0 and bytes_ar[i] <= 9:
        bytes_ar[i] += 48
      elif bytes_ar[i] >= 10 and bytes_ar[i] <= 35:
        bytes_ar[i] += 55
      else:
        bytes_ar[i] += 61
    
    return bytes_ar