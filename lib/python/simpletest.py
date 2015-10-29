import pyvkcrypto

hash = pyvkcrypto.scrypt(b"some plaintext",hard=True)
if (hash is not None):
    validation = pyvkcrypto.scryptcheck(hash,b"some plaintext",hard=True)
    assert (validation)
else:
    print("damn something bad happened")
    
encrypted = pyvkcrypto.scryptencrypt(b"some plaintext",b"password",hard=True)
if (encrypted is not None):
    decrypted = pyvkcrypto.scryptdecrypt(encrypted,b"password",hard=True)
    assert (b"some plaintext" == decrypted)
else:
    print("damn something bad happened 2")
    
publickey,privatekey = pyvkcrypto.genRSA2048();

encrypted = pyvkcrypto.RSAencrypt(publickey,True,b"Some fancy text to encrypt");
if (encrypted is not None):
    decrypted = pyvkcrypto.RSAdecrypt(privatekey,False,encrypted)
    assert (b"Some fancy text to encrypt" == decrypted)
else:
    print("damn something bad happened 3")
