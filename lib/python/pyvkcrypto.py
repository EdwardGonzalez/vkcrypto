import ctypes
import sys

DLL = ctypes.CDLL('/usr/local/lib/libvkcrypto.so')

VK_SCRYPT_HASH_LEN = 32
VK_SCRYPT_SALT_LEN = 16
VK_SCRYPT_LEN = 48
AES_BLOCK_SIZE = 16

def scrypt(plaintext,hard=False):
 buffer = ctypes.create_string_buffer(DLL.getScryptSize())
 status = DLL.scrypt(plaintext,len(plaintext),buffer,hard)
 if (status == 0):
  return buffer.raw
 else:
  return None;

def scryptcheck(scryptdata,plaintext,hard=False):
 return (DLL.scryptcheck(scryptdata,plaintext,len(plaintext),hard) == 0)

def scryptencrypt(plaintext,password,hard=False):
 buffer = ctypes.create_string_buffer(DLL.getScryptEncryptedSize(len(plaintext)))
 status = DLL.scryptencrypt(plaintext,len(plaintext),password,len(password),buffer,hard)
 if (status == 0):
  return buffer.raw
 else:
  return None

def scryptdecrypt(cipher,password,hard=False):
 reslen = DLL.getScryptDecryptedSize(len(cipher));
 buffer = ctypes.create_string_buffer(reslen);
 real_size = ctypes.c_uint()
 status = DLL.scryptdecrypt(cipher,len(cipher),password,len(password),buffer,ctypes.byref(real_size),hard);
 if (status == 0):
  return buffer.raw[:real_size.value]
 else:
  return None

def genRSA2048():
 genrsa = DLL.genRSA2048
 genrsa.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),ctypes.POINTER(ctypes.c_uint),
			ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),ctypes.POINTER(ctypes.c_uint)]
 pub = ctypes.POINTER(ctypes.c_ubyte)();
 pub_l = ctypes.c_uint(0)
 priv = ctypes.POINTER(ctypes.c_ubyte)();
 priv_l = ctypes.c_uint(0)
 status = genrsa(ctypes.byref(pub),ctypes.byref(pub_l),ctypes.byref(priv),ctypes.byref(priv_l));
 if (status == 0):

  if (sys.version_info.major >= 3):
    return ((bytes(pub[:pub_l.value]), bytes(priv[:priv_l.value])))

  pub_h = b''
  for i in range(0,pub_l.value):
   pub_h += chr(pub[i])

  priv_h = b''
  for i in range(0,priv_l.value):
   priv_h += chr(priv[i])

  return (pub_h,priv_h)
 else:
  return None

def RSAencrypt(key,public,plaintext):
 reslen = DLL.getRSAEncryptedSize(len(plaintext))
 buffer = ctypes.create_string_buffer(reslen)
 status = DLL.RSAencrypt(key,len(key),plaintext,len(plaintext),public,buffer)
 if (status == 0):
  return buffer.raw
 else:
  return None

def RSAdecrypt(key,public,cipher):
 reslen = DLL.getRSADecryptedSize(len(cipher))
 buffer = ctypes.create_string_buffer(reslen)
 real_size = ctypes.c_uint()
 status = DLL.RSAdecrypt(key,len(key),cipher,len(cipher),public,buffer,ctypes.byref(real_size))
 if (status == 0):
  return buffer.raw[:real_size.value]
 else:
  return None
