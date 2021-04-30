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
#include <srs_app_quic_transport.hpp>

string quic_conn_id_dump(const uint8_t* data, const size_t len)
{
    char capacity[256];
    char* buf = capacity;
    int size = 0;
    for (size_t i = 0; i < len; ++i) {
        int nb = snprintf(buf, sizeof(capacity), "%02x", data[i]);
        if (nb < 0)
            break;

        buf += nb;
        size += nb;
    }

    return string(capacity, size);
}

string quic_conn_id_dump(const string& connid)
{
    return quic_conn_id_dump(reinterpret_cast<const uint8_t*>(connid.data()), connid.size());
}

uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen, uint32_t version)
{
    uint32_t h = 0x811C9DC5u;
    const uint8_t *p = reinterpret_cast<const uint8_t*>(sa);
    const uint8_t *ep = p + salen;
    for (; p != ep; ++p) {
        h ^= *p;
        h *= 0x01000193u;
    }
    version = htonl(version);
    p = reinterpret_cast<const uint8_t*>(&version);
    ep = p + sizeof(version);
    for (; p != ep; ++p) {
        h ^= *p;
        h *= 0x01000193u;
    }
    h &= 0xF0F0F0F0u;
    h |= 0x0A0A0A0Au;
    return h;
}

ngtcp2_crypto_aead crypto_aead_aes_128_gcm()
{
  	ngtcp2_crypto_aead aead;
  	ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER*>(EVP_aes_128_gcm()));
  	return aead;
}

ngtcp2_crypto_md crypto_md_sha256()
{
  	ngtcp2_crypto_md md;
  	ngtcp2_crypto_md_init(&md, const_cast<EVP_MD*>(EVP_sha256()));
  	return md;
}

void ngtcp2_log_handle(void *user_data, const char *fmt, ...) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    if (! quic_transport->get_blocking()) {
        return;
    }

    va_list ap;

    static char buf[1024*12];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // TODO: FIXME: config if we log ngtcp2 quic log
    srs_trace("ngtcp2 quic log # %s", buf);
}

void qlog_handle(void *user_data, uint32_t flags, const void *data, size_t datalen)
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    if (! quic_transport->get_blocking()) {
        return;
    }

    // TODO: FIXME: config if we log qlog
    srs_trace("QLOG # %s", string(reinterpret_cast<const char*>(data), datalen).c_str());
}

string dump_quic_conn_stat(ngtcp2_conn* conn)
{
    ngtcp2_conn_stat stat;
    ngtcp2_conn_get_conn_stat(conn, &stat);
    stringstream ss;
    ss << "latest_rtt=" << stat.latest_rtt
       << ",min_rtt=" << stat.min_rtt
       << ",smoothed_rtt=" << stat.smoothed_rtt
       << ",rttvar=" << stat.rttvar
       << ",initial_rtt=" << stat.initial_rtt
       << ",first_rtt_sample_ts=" << stat.first_rtt_sample_ts
       << ",pto_count=" << stat.pto_count
       << ",loss_detection_timer=" << stat.loss_detection_timer
       << ",cwnd=" << stat.cwnd
       << ",ssthresh=" << stat.ssthresh
       << ",congestion_recovery_start_ts=" << stat.congestion_recovery_start_ts
       << ",bytes_in_flight=" << stat.bytes_in_flight
       << ",max_udp_payload_size=" << stat.max_udp_payload_size
       << ",delivery_rate_sec=" << stat.delivery_rate_sec;

    return ss.str();
}

int srs_generate_rand_data(uint8_t* dest, size_t destlen)
{
	for (size_t i = 0 ; i < destlen; ++i) {
        dest[i] = random() % 255;
	}
    return 0;
}

ngtcp2_tstamp srs_get_system_time_for_quic()
{
    // ngtcp2 using nano second.
    return srs_get_system_time() * 1000;
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
          	addr = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(sa)->sin_addr);
          	addrlen = sizeof(reinterpret_cast<const sockaddr_in*>(sa)->sin_addr);
          	break;
        case AF_INET6:
          	addr = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr);
          	addrlen = sizeof(reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr);
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
