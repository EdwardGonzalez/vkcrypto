/************************************************************************************
 * Copyright (C) 2015 by Edward González                                            *
 *                                                                                  *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy    *
 *  of this software and associated documentation files (the "Software"), to deal   *
 *  in the Software without restriction, including without limitation the rights    *
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell       *
 *  copies of the Software, and to permit persons to whom the Software is           *
 *  furnished to do so, subject to the following conditions:                        *
 *                                                                                  *
 *  The above copyright notice and this permission notice shall be included in      *
 *  all copies or substantial portions of the Software.                             *
 *                                                                                  *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR      *
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,        *
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE     *
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER          *
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   *
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN       *
 *  THE SOFTWARE.                                                                   *
 ************************************************************************************/

#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <libscrypt.h>

#include "vkcrypto.h"

#define VK_SCRYPT_N 16384
#define VK_SCRYPT_N_HARD 262144
#define VK_SCRYPT_r 8
#define VK_SCRYPT_p 1

#define VK_SCRYPT_HASH_LEN 32
#define VK_SCRYPT_SALT_LEN 16
#define VK_SCRYPT_LEN 48

#define RSA_LEN 2048
#define RSA_FACTOR 65537

//CRYPTO FUNCTIONS

/**
 * \brief Creates a scrypt hash
 * 
 * Creates a hash from a plaintext using the scrypt algorithm and outputs the data to a buffer
 * \param plaintext the plaintext buffer
 * \param plaintext_l the length of the plaintext
 * \param scrypt the scrypt hash output this buffer must hold getScryptSize() bytes
 * \param hard a boolean specifying the difficulty level to be hard or not
 * \return 1 for failure 0 for success
 */
int scrypt(const uint8_t* plaintext,size_t plaintext_l,uint8_t* scrypt,int hard){

	if (plaintext_l == 0) {
		return 1;
	}

	int saltRet;
	int hashRet;

	uint8_t saltbuf[VK_SCRYPT_SALT_LEN];
	saltRet = libscrypt_salt_gen(saltbuf,VK_SCRYPT_SALT_LEN);

	if (saltRet == -1) {
		return 1;
	} else {

		uint8_t hashbuf[VK_SCRYPT_HASH_LEN];
		hashRet = libscrypt_scrypt(plaintext,plaintext_l,saltbuf,
				VK_SCRYPT_SALT_LEN,(hard ? VK_SCRYPT_N_HARD : VK_SCRYPT_N),
				VK_SCRYPT_r, VK_SCRYPT_p, hashbuf, VK_SCRYPT_HASH_LEN);

		if (hashRet != 0) {
			return 1;
		} else {
			memcpy(scrypt, &saltbuf, VK_SCRYPT_SALT_LEN);
			memcpy(scrypt + VK_SCRYPT_SALT_LEN, &hashbuf, VK_SCRYPT_HASH_LEN);
			return 0;
		}
	}
}

/**
 * \brief Checks a scrypt hash generated with scrypt
 * 
 * Once you've created a scrypt hash, which also by default contains the salt, scrypt check tries to check a string to such hash
 * \param scrypt the scrypt buffer
 * \param plaintext the plaintext to test against
 * \param plaintext_l the length of the plaintext
 * \param hard a boolean specifying the difficulty level, if the scrypt hashing was created with hard=1 then the check must too
 * \return >=1 for failure 0 for success
 */
int scryptcheck(const uint8_t* scrypt,const uint8_t* plaintext,size_t plaintext_l,int hard){

	if (plaintext_l == 0) {
		return 1;
	}
	
	uint8_t salt[VK_SCRYPT_SALT_LEN];
	uint8_t hash[VK_SCRYPT_HASH_LEN];
	uint8_t hashcompare[VK_SCRYPT_HASH_LEN];

	memcpy(salt,scrypt,VK_SCRYPT_SALT_LEN);
	memcpy(hash,scrypt + VK_SCRYPT_SALT_LEN,VK_SCRYPT_HASH_LEN);


	int hashRet = libscrypt_scrypt(plaintext,plaintext_l,(uint8_t*)salt,
				VK_SCRYPT_SALT_LEN,(hard ? VK_SCRYPT_N_HARD : VK_SCRYPT_N),
				VK_SCRYPT_r, VK_SCRYPT_p, hashcompare, VK_SCRYPT_HASH_LEN);

	if (hashRet != 0) {
		return 1;
	} else {
		return (memcmp(hash,hashcompare,VK_SCRYPT_HASH_LEN));
	}
}

/**
 * \brief Encrypts data using scrypt and AES
 * 
 * This function uses AES256 CBC encryption with a scrypt hash for more security to avoid weak passwords
 * \param plaintext the plaintext to encrypt
 * \param plaintext_l the length of the plaintext
 * \param password the password to use
 * \param password_l the length of the password buffer
 * \param cipher the output ciphertext plus IV and SALT as a buffer, with len getScryptEncryptedSize(plaintext_l)
 * \param hard a boolean specifying the difficulty level to be hard or not
 * \return 1 for failure 0 for success
 */
int scryptencrypt(const uint8_t* plaintext,size_t plaintext_l,const uint8_t* password,size_t password_l,uint8_t* cipher,int hard){

	if (plaintext_l == 0 || password_l == 0) {
		return 1;
	}

	int saltRet;
	int hashRet;

	uint8_t saltbuf[VK_SCRYPT_SALT_LEN];
	saltRet = libscrypt_salt_gen(saltbuf,VK_SCRYPT_SALT_LEN);

	if (saltRet == -1) {
		return 1;
	} else {
		uint8_t hashbuf[VK_SCRYPT_HASH_LEN];
		hashRet = libscrypt_scrypt(password,password_l,saltbuf,
				VK_SCRYPT_SALT_LEN,(hard ? VK_SCRYPT_N_HARD : VK_SCRYPT_N), VK_SCRYPT_r, VK_SCRYPT_p, hashbuf, VK_SCRYPT_HASH_LEN);

		if (hashRet != 0) {
			return 1;
		} else {

			unsigned char iv[AES_BLOCK_SIZE];
			int rand_st = RAND_bytes(iv, AES_BLOCK_SIZE);
			if (rand_st <= 0){
				return 1;
			}
			
			const unsigned int result_len = ((plaintext_l + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

			unsigned char encrypted[result_len];
			memset(encrypted, 0, sizeof(encrypted));

			EVP_CIPHER_CTX *ctx;
			int len;
			unsigned int clen;
			if(!(ctx = EVP_CIPHER_CTX_new())){
				return 1;
			}
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, hashbuf, iv)){
				EVP_CIPHER_CTX_free(ctx);
				return 1;
			}
			if(1 != EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_l)){
				EVP_CIPHER_CTX_free(ctx);
				return 1;
			}
			clen = len;
			if(1 != EVP_EncryptFinal_ex(ctx, encrypted + len, &len)){
				EVP_CIPHER_CTX_free(ctx);
				return 1;
			}
			clen+=len;
			if (clen != result_len){
				return 1;
			}

			memcpy(cipher,&saltbuf,VK_SCRYPT_SALT_LEN);
			memcpy(cipher + VK_SCRYPT_SALT_LEN,&iv,AES_BLOCK_SIZE);
			memcpy(cipher + VK_SCRYPT_SALT_LEN + AES_BLOCK_SIZE,&encrypted,result_len);

			return 0;
		}
	}
}

/**
 * \brief Decrypts data from scrypt and AES
 * 
 * This function decrypts from AES256 CBC encryption with a scrypt hash for more security to avoid weak passwords
 * \param cipher the cipher to decrypt
 * \param cipher_l the length of the cipher buffer
 * \param password the password to use
 * \param password_l the length of the password buffer
 * \param plaintext the output plaintext with max len getScryptDecryptedSize(cipher_l)
 * \param plaintext_l the actual saved bytes in the plaintext buffer
 * \param hard a boolean specifying the difficulty level to be hard or not
 * \return 1 for failure 0 for success
 */
int scryptdecrypt(const uint8_t* cipher,size_t cipher_l,const uint8_t* password,size_t password_l,uint8_t* plaintext,size_t* plaintext_l,int hard){

	if (cipher_l <= VK_SCRYPT_SALT_LEN + AES_BLOCK_SIZE || password_l == 0) {
		return 1;
	}

	uint8_t saltbuf[VK_SCRYPT_SALT_LEN];
	uint8_t hashbuf[VK_SCRYPT_HASH_LEN];
	unsigned char iv[AES_BLOCK_SIZE];

	memcpy(saltbuf,cipher,VK_SCRYPT_SALT_LEN);
	memcpy(iv,cipher + VK_SCRYPT_SALT_LEN,AES_BLOCK_SIZE);
	
	int hashRet = libscrypt_scrypt(password,password_l,(uint8_t*)saltbuf,
			VK_SCRYPT_SALT_LEN,(hard ? VK_SCRYPT_N_HARD : VK_SCRYPT_N),
			VK_SCRYPT_r, VK_SCRYPT_p, hashbuf, VK_SCRYPT_HASH_LEN);

	if (hashRet != 0) {
		return 1;
	} else {

		EVP_CIPHER_CTX *ctx;
		int len;
		if(!(ctx = EVP_CIPHER_CTX_new())){
			return 1;
		}
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, hashbuf, iv)){
			EVP_CIPHER_CTX_free(ctx);
			return 1;
		}
		if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher + VK_SCRYPT_SALT_LEN + AES_BLOCK_SIZE, cipher_l - VK_SCRYPT_SALT_LEN - AES_BLOCK_SIZE)){
			EVP_CIPHER_CTX_free(ctx);
			return 1;
		}
		*plaintext_l = len;
		if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
			EVP_CIPHER_CTX_free(ctx);
			return 1;
		}
		*plaintext_l += len;
		return 0;
	}
}

/**
 * \brief Generates RSA 2048 bits private/public key counterparts
 * 
 * Generates RSA 2048 bits private/public key counterparts for usage for encryption and decryption in ANS1 hex format
 * \param pub a pointer to a buffer for the public key
 * \param pub_l the actual bytes saved in the public key
 * \param priv a pointer to a buffer for the private key
 * \param priv_l the actual bytes saved in the private key
 * \return 1 for failure 0 for success
 */
int genRSA2048(uint8_t **pub,size_t *pub_l,uint8_t **priv,size_t *priv_l){

	RSA *pRSA = NULL;
	pRSA = RSA_generate_key(RSA_LEN,RSA_FACTOR,NULL,NULL);

	if (pRSA){
		*pub_l = i2d_RSAPublicKey(pRSA,pub);
		*priv_l = i2d_RSAPrivateKey(pRSA,priv);
		return 0;
	} else {
		return 1;
	}
}

/**
 * \brief Encrypts using RSA
 * 
 * Encrypt data using a RSA public/private key using an AES256 CBC algorithm and a random password
 * \param key the key to use in ans1 format
 * \param key_l the length of the buffer key
 * \param plaintext the plaintext to encrypt
 * \param plaintext_l the plaintext buffer length
 * \param public specify public or private key
 * \param cipher the output ciphertext defined as size getRSAEncryptedSize(plaintext_l)
 * \return 1 for failure 0 for success
 */
int RSAencrypt(const uint8_t *key,size_t key_l,const uint8_t* plaintext,size_t plaintext_l,int public,uint8_t* cipher) {

	if (key_l == 0 || plaintext_l == 0){
		return 1;
	}

	unsigned char password[32];
	if (RAND_bytes(password,32) <= 0){
		return 1;
	}

	RSA *pRSA = NULL;

	unsigned char p_encrypted[256];
	int rsalen;
	if (public){
		if (!d2i_RSAPublicKey(&pRSA,(const unsigned char **)&key,key_l)){
			RSA_free(pRSA);
			return 1;
		}
		rsalen = RSA_public_encrypt(32,password,p_encrypted,pRSA,RSA_PKCS1_PADDING);
	} else {
		if (!d2i_RSAPrivateKey(&pRSA,(const unsigned char **)&key,key_l)){
			RSA_free(pRSA);
			return 1;
		}
		rsalen = RSA_private_encrypt(32,password,p_encrypted,pRSA,RSA_PKCS1_PADDING);
	}

	RSA_free(pRSA);
	
	if (rsalen < 0){
		return 1;
	}
	
	unsigned char iv[AES_BLOCK_SIZE];
	if (RAND_bytes(iv, AES_BLOCK_SIZE) <= 0){
		return 1;
	}

	const size_t result_len = ((plaintext_l + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char encrypted[result_len];
	memset(encrypted, 0, sizeof(encrypted));

	EVP_CIPHER_CTX *ctx;
	int len;
	unsigned int clen;
	if(!(ctx = EVP_CIPHER_CTX_new())){
		return 1;
	}
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, password, iv)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if(1 != EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plaintext_l)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	clen = len;
	if(1 != EVP_EncryptFinal_ex(ctx, encrypted + len, &len)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	clen+=len;
	if (clen != result_len){
		return 1;
	}

	memcpy(cipher,&p_encrypted,256);
	memcpy(cipher + 256,&iv,AES_BLOCK_SIZE);
	memcpy(cipher + 256 + AES_BLOCK_SIZE,&encrypted,result_len);
	return 0;
}

/**
 * \brief Decrypts using RSA
 * 
 * Decrypt data using a RSA public/private key using an AES256 CBC algorithm and a random password
 * \param key the key to use in ans1 format
 * \param key_l the length of the buffer key
 * \param cipher the ciphertext to decrypt
 * \param cipher_l the ciphertext buffer length
 * \param public specify public or private key for decryption
 * \param plaintext the output ciphertext defined as size getRSADecryptedSize(cipher_l)
 * \param plaintext_l the number of bytes actually written to such buffer
 * \return 1 for failure 0 for success
 */
int RSAdecrypt(const uint8_t *key,size_t key_l,const uint8_t* cipher,size_t cipher_l,int public,uint8_t* plaintext,size_t *plaintext_l) {

	unsigned char p_encrypted[256];
	unsigned char password[32];
	unsigned char iv[AES_BLOCK_SIZE];
	memcpy(p_encrypted,cipher,256);
	memcpy(iv,cipher + 256,AES_BLOCK_SIZE);

	RSA *pRSA = NULL;

	int rsalen;
	if (public){
		if (!d2i_RSAPublicKey(&pRSA,(const unsigned char **)&key,key_l)){
			RSA_free(pRSA);
			return 1;
		}
		rsalen = RSA_public_decrypt(256,p_encrypted,password,pRSA,RSA_PKCS1_PADDING);
	} else {
		if (!d2i_RSAPrivateKey(&pRSA,(const unsigned char **)&key,key_l)){
			RSA_free(pRSA);
			return 1;
		}
		rsalen = RSA_private_decrypt(256,p_encrypted,password,pRSA,RSA_PKCS1_PADDING);
	}

	RSA_free(pRSA);

	if (rsalen < 0){
		return 1;
	}

	EVP_CIPHER_CTX *ctx;
	int len;
	if(!(ctx = EVP_CIPHER_CTX_new())){
		return 1;
	}
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, password, iv)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher + 256 + AES_BLOCK_SIZE, cipher_l - 256 - AES_BLOCK_SIZE)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	*plaintext_l = len;
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
	*plaintext_l += len;
	return 0;
}

//HELPER FUNCTIONS

/**
 * \brief Provides the scrypt buffer hash size
 * 
 * \return VK_SCRYPT_LEN
 */
unsigned int getScryptSize() {
	return VK_SCRYPT_LEN;
}

/**
 * \brief Provides the encrypted size for an AES 256 CBC block
 * 
 * \return variable bytes
 */
unsigned int getScryptEncryptedSize(unsigned int decryptedsize) {
	return VK_SCRYPT_SALT_LEN + AES_BLOCK_SIZE + (((decryptedsize + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
}

/**
 * \brief Provides the maximum decrypted size for an AES 256 CBC block
 * 
 * \return variable bytes
 */
unsigned int getScryptDecryptedSize(unsigned int encryptedsize){
	if (encryptedsize <= VK_SCRYPT_SALT_LEN + AES_BLOCK_SIZE){return 0;}
	return encryptedsize - VK_SCRYPT_SALT_LEN - AES_BLOCK_SIZE;
}

/**
 * \brief Provides the encrypted size for an AES 256 CBC block plus RSA
 * 
 * \return variable bytes
 */
unsigned int getRSAEncryptedSize(unsigned int decryptedsize) {
	return 256 + AES_BLOCK_SIZE + (((decryptedsize + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
}

/**
 * \brief Provides the maximum decrypted size for an AES 256 CBC block plus RSA
 * 
 * \return variable bytes
 */
unsigned int getRSADecryptedSize(unsigned int encryptedsize){
	if (encryptedsize <= 256 + AES_BLOCK_SIZE){return 0;}
	return encryptedsize - AES_BLOCK_SIZE - 256;
}
