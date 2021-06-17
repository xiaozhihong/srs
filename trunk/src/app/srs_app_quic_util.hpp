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

#ifndef SRS_APP_QUIC_UTIL_HPP
#define SRS_APP_QUIC_UTIL_HPP

#include <srs_core.hpp>
#include <srs_kernel_utility.hpp>

#include <deque>
#include <string>
#include <map>
#include <vector>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

// Dump quic conn id from bin to hex format.
extern std::string quic_conn_id_dump(const uint8_t* data, const size_t len);
extern std::string quic_conn_id_dump(const std::string& connid);

extern uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen, uint32_t version);

// Lib ngtcp2 log handle.
extern void ngtcp2_log_handle(void *user_data, const char *fmt, ...);
// qlog handler
extern void qlog_handle(void *user_data, uint32_t flags, const void *data, size_t datalen);
// dump quic conn stat.
extern std::string dump_quic_conn_stat(ngtcp2_conn* conn);
// Generate |destlen| size random data and write to |dest|.
extern int srs_generate_rand_data(uint8_t* dest, size_t destlen);
// Return systime in ns resolution.
extern ngtcp2_tstamp srs_get_system_time_for_quic();

// TODO: FIXME: just for test.
const uint64_t kStreamDataSize = 10 * 1024 * 1024;

const size_t kTokenRandDatalen = 16;
const uint8_t kTokenMagic = 0x36;
const size_t kMaxTokenLen = 1 + sizeof(uint64_t) + 16 + kTokenRandDatalen;
const int kServerCidLen = 10;
const int kClientCidLen = 10;

// Helper function to generate ngtcp2_crypto_aead.
extern ngtcp2_crypto_aead crypto_aead_aes_128_gcm();
// Helper function to generate ngtcp2_crypto_md.
extern ngtcp2_crypto_md crypto_md_sha256();

// Helper class to generate quic token to verify client has validate addr.
class SrsQuicToken
{
public:
    SrsQuicToken();
    ~SrsQuicToken();
public:
    srs_error_t init();
    ngtcp2_crypto_aead token_aead() const { return token_aead_; }
    ngtcp2_crypto_md token_md() const { return token_md_; }
    uint8_t* get_static_secret() { return static_secret_; }
    size_t get_static_secret_len() { return sizeof(static_secret_); }
public:
    size_t generate_token_addr(uint8_t *dest, size_t destlen, const sockaddr *sa);
    int generate_secret(uint8_t *secret, size_t secretlen);
    int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen, const uint8_t *rand_data, size_t rand_datalen);
    int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa);

private:
    ngtcp2_crypto_aead token_aead_;
    ngtcp2_crypto_md token_md_;
    uint8_t static_secret_[32];
};

#endif
