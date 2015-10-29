#ifndef _VKCRYPTO_H_
#define _VKCRYPTO_H_

#ifdef __cplusplus
extern "C"{
#endif

int scrypt(const uint8_t* plaintext,size_t plaintext_l,uint8_t* scrypt,int hard);
int scryptcheck(const uint8_t* scrypt,const uint8_t* plaintext,size_t plaintext_l,int hard);
int scryptencrypt(const uint8_t* plaintext,size_t plaintext_l,const uint8_t* password,size_t password_l,uint8_t* cipher,int hard);
int scryptdecrypt(const uint8_t* cipher,size_t cipher_l,const uint8_t* password,size_t password_l,uint8_t* plaintext,size_t* plaintext_l,int hard);
int genRSA2048(uint8_t **pub,size_t *pub_l,uint8_t **priv,size_t *priv_l);
int RSAencrypt(const uint8_t *key,size_t key_l,const uint8_t* plaintext,size_t plaintext_l,int public,uint8_t* cipher);
int RSAdecrypt(const uint8_t *key,size_t key_l,const uint8_t* cipher,size_t cipher_l,int public,uint8_t* plaintext,size_t *plaintext_l);
unsigned int getScryptSize();
unsigned int getScryptEncryptedSize(unsigned int decryptedsize);
unsigned int getScryptDecryptedSize(unsigned int encryptedsize);
unsigned int getRSAEncryptedSize(unsigned int decryptedsize);
unsigned int getRSADecryptedSize(unsigned int encryptedsize);

#ifdef __cplusplus
}
#endif

#endif /* !_VKCRYPTO_H_ */
