/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2020 John
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <srs_app_quic_util.hpp>

using namespace std;

#include <srs_core_autofree.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_config.hpp>
#include <srs_app_server.hpp>
#include <srs_app_quic_server.hpp>
#include <srs_service_utility.hpp>
#include <srs_service_st.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_tls.hpp>

ngtcp2_crypto_aead crypto_aead_aes_128_gcm()
{
  	ngtcp2_crypto_aead aead;
  	ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));
  	return aead;
}

ngtcp2_crypto_md crypto_md_sha256()
{
  	ngtcp2_crypto_md md;
  	ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));
  	return md;
}

void quic_log_printf(void *user_data, const char *fmt, ...) 
{
    va_list ap;

    static char buf[1024*12];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    srs_trace("ngtcp2 quic log # %s", buf);
}

int srs_generate_rand_data(uint8_t* dest, size_t destlen)
{
		for (size_t i = 0 ; i < destlen; ++i) {
        dest[i] = random() % 255;
	  }
    return 0;
}

SrsQuicToken::SrsQuicToken()
{
}

SrsQuicToken::~SrsQuicToken()
{
}

srs_error_t SrsQuicToken::init()
{
    srs_error_t err = srs_success;

    token_aead_ = crypto_aead_aes_128_gcm();
    token_md_ = crypto_md_sha256();

    if (generate_secret(static_secret_, sizeof(static_secret_)) != 0) {
        return srs_error_new(ERROR_QUIC_TOKEN, "generate token failed");
    }

    return err;
}

size_t SrsQuicToken::generate_token_addr(uint8_t *dest, size_t destlen, const sockaddr *sa) 
{
  	const uint8_t *addr = NULL;
  	size_t addrlen = 0;

  	switch (sa->sa_family) {
  			case AF_INET:
  			  	addr = reinterpret_cast<const uint8_t *>(
  			  	    &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
  			  	addrlen = sizeof(reinterpret_cast<const sockaddr_in *>(sa)->sin_addr);
  			  	break;
  			case AF_INET6:
  			  	addr = reinterpret_cast<const uint8_t *>(
  			  	    &reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
  			  	addrlen = sizeof(reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
  			  	break;
  			default:
  			  	return -1;
  	}

    if (addr == NULL || addrlen > destlen) {
        return -1;
    }

		memcpy(dest, addr, addrlen);
    return addrlen;
}

int SrsQuicToken::generate_secret(uint8_t *secret, size_t secretlen) 
{
		uint8_t rand[16];
		uint8_t md[32];

    srs_assert(sizeof(md) == secretlen);

    srs_generate_rand_data(rand, sizeof(rand));

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    unsigned int mdlen = sizeof(md);
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, rand, sizeof(rand)) ||
        !EVP_DigestFinal_ex(ctx, md, &mdlen)) {
        return -1;
    }

    memcpy(md, secret, secretlen);
    return 0;
}

int SrsQuicToken::derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
        size_t &ivlen, const uint8_t *rand_data, size_t rand_datalen) 
{
    uint8_t secret[32];

  	if (ngtcp2_crypto_hkdf_extract(secret, &token_md_, static_secret_,
  	        sizeof(static_secret_), rand_data, rand_datalen) != 0) {
  	  	return -1;
  	}

  	keylen = ngtcp2_crypto_aead_keylen(&token_aead_);
  	ivlen = ngtcp2_crypto_packet_protection_ivlen(&token_aead_);

  	if (ngtcp2_crypto_derive_packet_protection_key(key, iv, NULL, &token_aead_,
  	        &token_md_, secret, sizeof(secret)) != 0) {
  	    return -1;
  	}

  	return 0;
}

int SrsQuicToken::generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa) 
{
    uint8_t plaintext[8];
    uint64_t t = srs_get_system_startup_time();

    uint8_t addr[256];
    size_t addrlen = generate_token_addr(addr, sizeof(addr), sa);

    uint8_t* p = plaintext;
    memcpy(p, reinterpret_cast<uint8_t*>(&t), sizeof(t));
    p += sizeof(t);

    uint8_t rand_data[kTokenRandDatalen];
    uint8_t key[32];
    size_t keylen = sizeof(key);
    uint8_t iv[32];
    size_t ivlen = sizeof(iv);

    srs_generate_rand_data(rand_data, sizeof(rand_data));

    if (derive_token_key(key, keylen, iv, ivlen, rand_data, sizeof(rand_data)) != 0) {
        return -1;
    }

    size_t plaintextlen = sizeof(uint64_t); 
    ngtcp2_crypto_aead_ctx aead_ctx;
    if (ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &token_aead_, key, ivlen) != 0) {
        return -1;
    }

    token[0] = kTokenMagic;
    int ret = ngtcp2_crypto_encrypt(token + 1, &token_aead_, &aead_ctx,
        plaintext, plaintextlen, iv, ivlen, addr, addrlen);

    ngtcp2_crypto_aead_ctx_free(&aead_ctx);

    if (ret != 0) {
        return -1;
    }

    tokenlen = 1 + plaintextlen + token_aead_.max_overhead;
    memcpy(token + tokenlen, rand_data, sizeof(rand_data));
    tokenlen += sizeof(rand_data);

    return 0;
}
