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

#include <srs_app_quic_tls.hpp>

using namespace std;

#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_quic_conn.hpp>
#include <srs_app_server.hpp>
#include <srs_service_utility.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_conn.hpp>
#include <srs_app_quic_client.hpp>

#include <openssl/err.h>

#include <ngtcp2/ngtcp2_crypto_openssl.h>

const string kDefaultCiphers = 
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256";

const string kDefaultGroups = "X25519:P-256:P-384:P-521";

const string kHqAlpnDraft29 = "\x5hq-29";
const string kHqAlpnDraft30 = "\x5hq-30";
const string kHqAlpnDraft31 = "\x5hq-31";
const string kHqAlpnDraft32 = "\x5hq-32";
const string kHqAlph = kHqAlpnDraft29 + kHqAlpnDraft30 + kHqAlpnDraft31 + kHqAlpnDraft32;

// TODO: FIXME: quic have other draft

const uint32_t QUIC_VER_DRAFT29 = 0xFF00001DU;
const uint32_t QUIC_VER_DRAFT30 = 0xFF00001EU;
const uint32_t QUIC_VER_DRAFT31 = 0xFF00001FU;
const uint32_t QUIC_VER_DRAFT32 = 0xFF000020U;

namespace srs_ssl_quic_common {

static int flush_flight(SSL *ssl) 
{ 
    return 1; 
}

static int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) 
{
  	SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(SSL_get_app_data(ssl));
  	quic_transport->set_tls_alert(alert);

  	return 1;
}

} // namespace srs_ssl_quic_common


namespace srs_ssl_quic_server {

static int alpn_select_proto_hq_cb(SSL *ssl, const uint8_t **out,
                                  uint8_t *outlen, const uint8_t *in,
                                  unsigned int inlen, void *arg) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(SSL_get_app_data(ssl));
    const uint8_t *alpn;
    size_t alpnlen;
    uint32_t version = ngtcp2_conn_get_negotiated_version(quic_transport->conn());

    switch (version) {
    	case QUIC_VER_DRAFT29:
    	  	alpn = reinterpret_cast<const uint8_t *>(kHqAlpnDraft29.data());
    	  	alpnlen = kHqAlpnDraft29.size();
    	  	break;
    	case QUIC_VER_DRAFT30:
    	  	alpn = reinterpret_cast<const uint8_t *>(kHqAlpnDraft30.data());
    	  	alpnlen = kHqAlpnDraft30.size();
    	  	break;
    	case QUIC_VER_DRAFT31:
    	  	alpn = reinterpret_cast<const uint8_t *>(kHqAlpnDraft31.data());
    	  	alpnlen = kHqAlpnDraft31.size();
    	  	break;
    	case QUIC_VER_DRAFT32:
    	  	alpn = reinterpret_cast<const uint8_t *>(kHqAlpnDraft32.data());
    	  	alpnlen = kHqAlpnDraft32.size();
    	  	break;
    	default:
            srs_warn("unsupport quic version=%u", version);
    		return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    for (const uint8_t* p = in; p + alpnlen <= in + inlen; p += *p + 1) {
        if (memcmp(alpn, p, alpnlen) == 0) {
      	  	*out = p + 1;
      	  	*outlen = *p;
            srs_info("quic choose alpn %s", 
                string(reinterpret_cast<const char*>(*out), (size_t)(*outlen)).c_str());
      	  	return SSL_TLSEXT_ERR_OK;
      	}
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
}


static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) 
{
  	SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(SSL_get_app_data(ssl));
  	ngtcp2_crypto_level level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

    int ret = quic_transport->on_rx_key(level, read_secret, secret_len);
    if (ret != 0) {
        return 0;
    }
  	if (write_secret) {
        ret = quic_transport->on_tx_key(level, write_secret, secret_len);
        if (ret != 0) {
            return 0;
        }
  	  	if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION && 
            quic_transport->on_application_tx_key() != 0) {
  	    		return 0;
  	  	}
  	}

  	return 1;
}

static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) 
{
  	SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(SSL_get_app_data(ssl));
  	ngtcp2_crypto_level level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  	quic_transport->write_handshake(level, data, len);

  	return 1;
}

} // namespace srs_ssl_quic_server

namespace srs_ssl_quic_client
{

static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) 
{
  	SrsQuicClient* quic_transport = static_cast<SrsQuicClient*>(SSL_get_app_data(ssl));
  	ngtcp2_crypto_level level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

    if (read_secret) {
        if (quic_transport->on_rx_key(level, read_secret, secret_len) != 0) {
            return 0;
        }
  	  	if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION && 
            quic_transport->on_application_tx_key() != 0) {
  	    		return 0;
  	  	}
    }

    if (quic_transport->on_tx_key(level, write_secret, secret_len) != 0) {
        return 0;
    }

  	return 1;
}

static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                       const uint8_t *data, size_t len) 
{
  	SrsQuicClient* quic_transport = static_cast<SrsQuicClient*>(SSL_get_app_data(ssl));
  	ngtcp2_crypto_level level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  	quic_transport->write_handshake(level, data, len);

  	return 1;
}

} // namespace srs_ssl_quic_client

SSL_QUIC_METHOD ssl_quic_server_method = 
{
    .set_encryption_secrets = srs_ssl_quic_server::set_encryption_secrets,
    .add_handshake_data = srs_ssl_quic_server::add_handshake_data,
    .flush_flight = srs_ssl_quic_common::flush_flight,
    .send_alert = srs_ssl_quic_common::send_alert
};

SSL_QUIC_METHOD ssl_quic_client_method = 
{
    .set_encryption_secrets = srs_ssl_quic_client::set_encryption_secrets,
    .add_handshake_data = srs_ssl_quic_client::add_handshake_data,
    .flush_flight = srs_ssl_quic_common::flush_flight,
    .send_alert = srs_ssl_quic_common::send_alert
};

SrsQuicTlsContext::SrsQuicTlsContext()
{
    ssl_ctx_ = NULL;
}

SrsQuicTlsContext::~SrsQuicTlsContext()
{
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
    }
}

SrsQuicTlsClientContext::SrsQuicTlsClientContext()
    : SrsQuicTlsContext()
{
}

SrsQuicTlsClientContext::~SrsQuicTlsClientContext()
{
}

srs_error_t SrsQuicTlsClientContext::init(const std::string& key, const std::string& cert)
{
    srs_error_t err = srs_success;

    ssl_ctx_ = SSL_CTX_new(TLS_client_method());

    if (ssl_ctx_ == NULL) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_new failed, err=%s",
            ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

    SSL_CTX_set_default_verify_paths(ssl_ctx_);

    if (SSL_CTX_set_ciphersuites(ssl_ctx_, kDefaultCiphers.c_str()) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_set_ciphersuites failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    if (SSL_CTX_set1_groups_list(ssl_ctx_, kDefaultGroups.c_str()) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_set1_groups_list failed, err=%s",
            ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_quic_method(ssl_ctx_, &ssl_quic_client_method);

    srs_trace("QUIC SSL client context init success");

    return err;
}

SrsQuicTlsServerContext::SrsQuicTlsServerContext()
    : SrsQuicTlsContext()
{
}

SrsQuicTlsServerContext::~SrsQuicTlsServerContext()
{
}

srs_error_t SrsQuicTlsServerContext::init(const std::string& key, const std::string& cert)
{
    srs_error_t err = srs_success;

    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx_ == NULL) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_new failed, err=%s",
            ERR_error_string(ERR_get_error(), NULL));
    }

    unsigned long ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                              SSL_OP_SINGLE_ECDH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE |
                              SSL_OP_NO_ANTI_REPLAY;

    SSL_CTX_set_options(ssl_ctx_, ssl_opts);

    if (SSL_CTX_set_ciphersuites(ssl_ctx_, kDefaultCiphers.c_str()) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_set_ciphersuites failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    if (SSL_CTX_set1_groups_list(ssl_ctx_, kDefaultGroups.c_str()) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_set1_groups_list failed, err=%s",
            ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

    SSL_CTX_set_alpn_select_cb(ssl_ctx_, srs_ssl_quic_server::alpn_select_proto_hq_cb, NULL);

    SSL_CTX_set_default_verify_paths(ssl_ctx_);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_use_PrivateKey_file failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cert.c_str()) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_use_certificate_chain_file failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_CTX_check_private_key failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    const string kSessoinIdCtx = "SRS QUIC Server";
    SSL_CTX_set_session_id_context(ssl_ctx_, 
        reinterpret_cast<const uint8_t*>(kSessoinIdCtx.data()), kSessoinIdCtx.size());

    SSL_CTX_set_max_early_data(ssl_ctx_, UINT32_MAX);
    SSL_CTX_set_quic_method(ssl_ctx_, &ssl_quic_server_method);

    srs_trace("QUIC SSL server context init success");

    return err;
}

SrsQuicTlsSession::SrsQuicTlsSession()
{
    ssl_ = NULL;
}

SrsQuicTlsSession::~SrsQuicTlsSession()
{
    if (ssl_) {
        SSL_free(ssl_);
    }
}

SrsQuicTlsClientSession::SrsQuicTlsClientSession()
    : SrsQuicTlsSession()
{
}

SrsQuicTlsClientSession::~SrsQuicTlsClientSession()
{
}

srs_error_t SrsQuicTlsClientSession::init(const SrsQuicTlsContext* quic_tls_ctx, void* handler)
{
    srs_error_t err = srs_success;

    SSL_CTX* ssl_ctx = quic_tls_ctx->get_ssl_ctx();
    ssl_ = SSL_new(ssl_ctx);
    if (ssl_ == NULL) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_new failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_set_app_data(ssl_, handler);
    SSL_set_connect_state(ssl_);

    SSL_set_alpn_protos(ssl_, reinterpret_cast<const uint8_t*>(kHqAlph.data()), kHqAlph.size());

    // TODO: FIXME: have better name? or config host name.
    SSL_set_tlsext_host_name(ssl_, "127.0.0.1");

    if (false) {
        SSL_set_msg_callback(ssl_, SSL_trace);
        SSL_set_msg_callback_arg(ssl_, BIO_new_fp(stdout, 0));
    }

    return err;
}

SrsQuicTlsServerSession::SrsQuicTlsServerSession()
    : SrsQuicTlsSession()
{
}

SrsQuicTlsServerSession::~SrsQuicTlsServerSession()
{
}

srs_error_t SrsQuicTlsServerSession::init(const SrsQuicTlsContext* quic_tls_ctx, void* handler)
{
    srs_error_t err = srs_success;

    SSL_CTX* ssl_ctx = quic_tls_ctx->get_ssl_ctx();
    ssl_ = SSL_new(ssl_ctx);
    if (ssl_ == NULL) {
        return srs_error_new(ERROR_QUIC_TLS, "SSL_new failed, err=%s", 
            ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_set_app_data(ssl_, handler);
    SSL_set_accept_state(ssl_);
    SSL_set_quic_early_data_enabled(ssl_, 1);

    if (false) {
        SSL_set_msg_callback(ssl_, SSL_trace);
        SSL_set_msg_callback_arg(ssl_, BIO_new_fp(stdout, 0));
    }

    return err;
}
