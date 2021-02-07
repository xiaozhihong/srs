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

#include <srs_app_quic_conn.hpp>

using namespace std;

#include <ngtcp2/ngtcp2_crypto.h>

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
#include <srs_app_quic_util.hpp>

const int kServerScidLen = 18;

static int cb_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
    const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) 
{
  	if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
  	  	return NGTCP2_ERR_CALLBACK_FAILURE;
  	}
  	return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
    return quic_conn->recv_stream_data(flags, stream_id, offset, data, datalen);
}

static int cb_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data)
{
    return ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
}


static int cb_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
    return quic_conn->recv_crypto_data(crypto_level, data, datalen);
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
    return quic_conn->handshake_completed();
}

static int cb_acked_crypto_offset(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, uint64_t datalen, void *user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
    return quic_conn->acked_crypto_offset(crypto_level, offset, datalen);
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data) 
{
    return 0;
}

static int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
  	return quic_conn->on_stream_open(stream_id);
}

static int cb_stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
    void *user_data, void *stream_user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
  	return quic_conn->on_stream_close(stream_id, app_error_code);
}

static int cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx,
    ngtcp2_rand_usage usage)
{
      return generate_rand_data(dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
    size_t cidlen, void *user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
  	return quic_conn->get_new_connection_id(cid, token, cidlen);
}

static int cb_path_validation(ngtcp2_conn *conn, const ngtcp2_path *path,
				ngtcp2_path_validation_result res, void *user_data) 
{
    return 0;
}

static int cb_stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
    uint64_t app_error_code, void *user_data, void *stream_user_data) 
{
    return 0;
}

static int cb_extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) 
{
    return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t max_data, void *user_data, void *stream_user_data) 
{
  	return 0;
}

static int cb_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, 
    uint8_t *tx_iv, const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, 
    size_t secretlen, void *user_data) 
{
    SrsQuicConnection* quic_conn = static_cast<SrsQuicConnection *>(user_data);
  	return quic_conn->update_key(rx_secret, tx_secret, rx_aead_ctx, rx_iv, 
        tx_aead_ctx, tx_iv, current_tx_secret, current_rx_secret, secretlen);
}

SrsQuicConnection::SrsQuicConnection(SrsQuicServer* s, const SrsContextId& cid)
{
    disposing_ = false;

    _srs_quic_manager->subscribe(this);

    cid_ = cid;
    server_ = s;
    timer_ = new SrsHourGlass(this, 10 * SRS_UTIME_MILLISECONDS);
    sendonly_skt_ = NULL;

    conn_ = NULL;

    tls_server_session_ = new SrsQuicTlsServerSession();
}

SrsQuicConnection::~SrsQuicConnection()
{
		_srs_quic_manager->unsubscribe(this);

    srs_freep(timer_);
    srs_freep(sendonly_skt_);

    srs_freep(tls_server_session_);
}

void SrsQuicConnection::update_sendonly_socket(SrsUdpMuxSocket* skt)
{
    // TODO: FIXME: Refine performance.
    string prev_peer_id, peer_id = skt->peer_id();
    if (sendonly_skt_) {
        prev_peer_id = sendonly_skt_->peer_id();
    }

    // Ignore if same address.
    if (prev_peer_id == peer_id) {
        return;
    }

    srs_freep(sendonly_skt_);
    sendonly_skt_ = skt->copy_sendonly();
}

ngtcp2_path SrsQuicConnection::build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
    sockaddr* remote_addr, const socklen_t remote_addrlen)
{
    ngtcp2_path path;
    path.local.addr = local_addr;
    path.local.addrlen = local_addrlen;
    path.local.user_data = NULL;
    path.remote.addr = remote_addr;
    path.remote.addrlen = remote_addrlen;
    path.remote.user_data = NULL;

    return path;
}

ngtcp2_callbacks SrsQuicConnection::build_quic_callback()
{
    ngtcp2_callbacks callback;
    callback.client_initial = NULL;
    callback.recv_client_initial = cb_recv_client_initial_cb;
    callback.recv_crypto_data = cb_recv_crypto_data;
    callback.handshake_completed = cb_handshake_completed;
    callback.recv_version_negotiation = NULL;
    callback.encrypt = ngtcp2_crypto_encrypt_cb;
    callback.decrypt = ngtcp2_crypto_decrypt_cb;
    callback.hp_mask = cb_hp_mask;
    callback.recv_stream_data = cb_recv_stream_data;
    callback.acked_crypto_offset = cb_acked_crypto_offset;
    callback.acked_stream_data_offset = cb_acked_stream_data_offset;
    callback.stream_open = cb_stream_open;
    callback.stream_close = cb_stream_close;
    callback.recv_stateless_reset = NULL;
    callback.recv_retry = NULL;
    callback.extend_max_local_streams_bidi = NULL;
    callback.extend_max_local_streams_uni = NULL;
    callback.rand = cb_rand;
    callback.get_new_connection_id = cb_get_new_connection_id;
    callback.remove_connection_id = NULL;
    callback.update_key = cb_update_key;
    callback.path_validation = cb_path_validation;
    callback.select_preferred_addr = NULL;
    callback.stream_reset = cb_stream_reset;
    callback.extend_max_remote_streams_bidi = cb_extend_max_remote_streams_bidi;
    callback.extend_max_remote_streams_uni = NULL;
    callback.extend_max_stream_data = cb_extend_max_stream_data;
    callback.dcid_status = NULL;
    callback.handshake_confirmed = NULL;
    callback.recv_new_token = NULL;
    callback.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callback.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;

    return callback;
}

ngtcp2_settings SrsQuicConnection::build_quic_settings()
{
}

srs_error_t SrsQuicConnection::init(SrsUdpMuxSocket* skt, ngtcp2_pkt_hd* hd)
{
    srs_error_t err = srs_success;

    cb_ = build_quic_callback();

    ngtcp2_settings_default(&settings_);
    settings_.log_printf = quic_log_printf;
		settings_.initial_ts = srs_get_system_time();
  	settings_.token.base = hd->token.base;
  	settings_.token.len = hd->token.len;
  	settings_.max_udp_payload_size = NGTCP2_MAX_PKTLEN_IPV4;
  	settings_.cc_algo = NGTCP2_CC_ALGO_CUBIC;
  	settings_.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;

		ngtcp2_transport_params& params = settings_.transport_params;
  	params.initial_max_stream_data_bidi_local = 256 * 1024;
  	params.initial_max_stream_data_bidi_remote = 256 * 1024;
  	params.initial_max_stream_data_uni = 256 * 1024;;
  	params.initial_max_data = 1 * 1024 * 1024;
  	params.initial_max_streams_bidi = 100;
  	params.initial_max_streams_uni = 3;
  	params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  	params.stateless_reset_token_present = 1;
  	params.active_connection_id_limit = 7;
    params.original_dcid = hd->dcid;

    // TODO: FIXME:
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr*>(server_->local_addr());
    path.local.addrlen = server_->local_addrlen();
    path.local.user_data = NULL;
    path.remote.addr = reinterpret_cast<sockaddr*>(skt->peer_addr());
    path.remote.addrlen = skt->peer_addrlen();
    path.remote.user_data = NULL;

    scid_.datalen = kServerScidLen;
		for (size_t i = 0 ; i < scid_.datalen; ++i) {
        scid_.data[i] = random() % 255;
	  }

    int ret = ngtcp2_conn_server_new(&conn_, &hd->scid, &scid_, &path,
        hd->version, &cb_, &settings_, NULL, this);

    if (ret != 0) {
				return srs_error_new(ERROR_QUIC_CONN, "new quic conn failed,ret=%d", ret);
    }

    if ((err = tls_server_session_->init(server_->get_quic_tls_server_ctx(), this)) != srs_success) {
        return srs_error_wrap(err, "tls session init failed");
    }

    ngtcp2_conn_set_tls_native_handle(conn_, tls_server_session_->get_ssl());

    // TODO: FIXME: need schecule
    if ((err = timer_->tick(1, 10 * SRS_UTIME_MILLISECONDS)) != srs_success) {
        return srs_error_wrap(err, "quic tick");
    }

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "timer start failed");
    }

    update_sendonly_socket(skt);

    return err;
}

srs_error_t SrsQuicConnection::on_data(SrsUdpMuxSocket* skt, const uint8_t* data, size_t size)
{
    srs_error_t err = srs_success;

    update_sendonly_socket(skt);

    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr*>(server_->local_addr());
    path.local.addrlen = server_->local_addrlen();
    path.local.user_data = NULL;
    path.remote.addr = reinterpret_cast<sockaddr*>(skt->peer_addr());
    path.remote.addrlen = skt->peer_addrlen();
    path.remote.user_data = NULL;

		ngtcp2_pkt_info pkt_info;
		int ret = ngtcp2_conn_read_pkt(conn_, &path, &pkt_info, data, size, srs_get_system_time());
		if (ret != 0) {
    		switch (ret) {
    				case NGTCP2_ERR_DRAINING:
    				case NGTCP2_ERR_RETRY:
    				case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
    				case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
    				case NGTCP2_ERR_TRANSPORT_PARAM:
    				case NGTCP2_ERR_DROP_CONN:
    				default: break;
    		}
				return srs_error_new(ERROR_QUIC_DATA, "quic read packet failed,ret=%d", ret);
		}

    try_to_write();
    return err;
}

std::string SrsQuicConnection::get_connid()
{
    if (conn_ == NULL) {
        return "";
    }

    return string(reinterpret_cast<const char*>(scid_.data), scid_.datalen);
}

bool SrsQuicConnection::is_alive()
{
    return true;
}

void SrsQuicConnection::on_before_dispose(ISrsResource* c)
{
    if (disposing_) {
        return;
    }

    SrsQuicConnection* quic_conn = dynamic_cast<SrsQuicConnection*>(c);
    if (quic_conn == this) {
        disposing_ = true;
    }

    if (quic_conn && quic_conn == this) {
        _srs_context->set_id(cid_);
        srs_trace("QUIC: quic_conn detach from [%s](%s), disposing=%d", c->get_id().c_str(),
            c->desc().c_str(), disposing_);
    }
}

void SrsQuicConnection::on_disposing(ISrsResource* c)
{
    if (disposing_) {
        return;
    }
}

const SrsContextId& SrsQuicConnection::get_id()
{
    return cid_;
}

std::string SrsQuicConnection::desc()
{
    return "QuicConn";
}

void SrsQuicConnection::switch_to_context()
{
    _srs_context->set_id(cid_);
}

const SrsContextId& SrsQuicConnection::context_id()
{
    return cid_;
}

int SrsQuicConnection::on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
{
    if (ngtcp2_crypto_derive_and_install_rx_key(conn_, NULL, NULL, NULL, 
            level, secret, secretlen) != 0) {
        srs_error("ngtcp2_crypto_derive_and_install_rx_key failed");
        return -1;
    }
  
    switch (level) {
        case NGTCP2_CRYPTO_LEVEL_EARLY:
        case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
        case NGTCP2_CRYPTO_LEVEL_APPLICATION:
            break;
        default:
            srs_error("level invalid");
            return -1;
    }
  
    return 0;
}

int SrsQuicConnection::on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
{
    if (ngtcp2_crypto_derive_and_install_tx_key(conn_, NULL, NULL, NULL,
            level, secret, secretlen) != 0) {
        srs_error("ngtcp2_crypto_derive_and_install_tx_key failed");
        return -1;
    }

    switch (level) {
        case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
          break;
        case NGTCP2_CRYPTO_LEVEL_APPLICATION:
          break;
        case NGTCP2_CRYPTO_LEVEL_EARLY:
        default:
            srs_error("level invalid");
            return -1;
    }

    return 0;
}

int SrsQuicConnection::on_application_tx_key()
{
    return 0;
}

int SrsQuicConnection::write_server_handshake(ngtcp2_crypto_level level, 
        const uint8_t *data, size_t datalen) 
{
    SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)level];
    crypto.data.push_back(string(reinterpret_cast<const char*>(data), datalen));

    string& buf = crypto.data.back();
    ngtcp2_conn_submit_crypto_data(conn_, level, reinterpret_cast<const uint8_t*>(buf.data()), buf.size());

    return 0;
}

int SrsQuicConnection::acked_crypto_offset(ngtcp2_crypto_level crypto_level,
                                        uint64_t offset, uint64_t datalen) 
{
  	SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)crypto_level];

    for (deque<string>& d = crypto.data; ! d.empty() && crypto.acked_offset + d.front().size() <= offset + datalen;) {
        string& v = d.front();
        crypto.acked_offset += v.size();
        d.pop_front();
    }
    return 0;
}

void SrsQuicConnection::set_tls_alert(uint8_t alert)
{
    // TODO: FIXME:
}

int SrsQuicConnection::recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, 
        const uint8_t *data, size_t datalen)
{
    srs_trace("stream %ld recv %u bytes", stream_id, datalen);
    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn_, datalen);

    return 0;
}

int SrsQuicConnection::recv_crypto_data(ngtcp2_crypto_level crypto_level, 
        const uint8_t* data, size_t datalen)
{
    int ret = ngtcp2_crypto_read_write_crypto_data(conn_, crypto_level, data, datalen);
    if (ret != 0) {
        if ((ret = ngtcp2_conn_get_tls_error(conn_)) != 0) {
            srs_error("quic tls error");
            return ret;
        }
        return NGTCP2_ERR_CRYPTO;
    }

    return 0;
}

int SrsQuicConnection::handshake_completed()
{
    srs_trace("quic handshake completed");
		uint8_t token[kMaxTokenLen];
    size_t tokenlen = sizeof(token);
    if (server_->get_quic_token()->generate_token(token, tokenlen, (const sockaddr*)sendonly_skt_->peer_addr()) != 0) {
        return 0;
    }

    int ret = ngtcp2_conn_submit_new_token(conn_, token, tokenlen);
    if (ret != 0) {
        srs_error("ngtcp2_conn_submit_new_token failed, ret=%d", ret);
        return -1;
    }

    return 0;
}

int SrsQuicConnection::on_stream_open(int64_t stream_id)
{
		srs_trace("stream %ld open", stream_id);
    return 0;
}

int SrsQuicConnection::on_stream_close(int64_t stream_id, uint64_t app_error_code)
{
		srs_trace("stream %ld close, app_error_code=%lu", stream_id, app_error_code);
    return 0;
}

int SrsQuicConnection::get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen)
{
    // TODO: FIXME:
    cid->datalen = cidlen;
		for (size_t i = 0 ; i < cid->datalen; ++i) {
        cid->data[i] = random() % 255;
	  }
    ngtcp2_crypto_md md = crypto_md_sha256();
    if (ngtcp2_crypto_generate_stateless_reset_token(token, &md, server_->get_quic_token()->get_static_secret(), 
            server_->get_quic_token()->get_static_secret_len(), cid) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int SrsQuicConnection::update_key(uint8_t *rx_secret, uint8_t *tx_secret,
        ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
        const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen) 
{
		uint8_t rx_key[64];
		uint8_t tx_key[64];

  	if (ngtcp2_crypto_update_key(conn_, rx_secret, tx_secret, rx_aead_ctx,
                               rx_key, rx_iv, tx_aead_ctx, tx_key,
                               tx_iv, current_rx_secret, current_tx_secret,
                               secretlen) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
  	}

    return 0;
}

srs_error_t SrsQuicConnection::notify(int type, srs_utime_t interval, srs_utime_t tick)
{
    return try_to_write();
}

srs_error_t SrsQuicConnection::try_to_write()
{
    srs_error_t err = srs_success;

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        srs_warn("quic conn is closing");
        return err;
    }

    if (ngtcp2_conn_is_in_draining_period(conn_)) {
        srs_warn("quic conn is draining");
        return err;
    }

    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
		ngtcp2_ssize ndatalen;

    ngtcp2_vec vec;
    ngtcp2_pkt_info pi;
    sockaddr_storage local_addr_storage;
    sockaddr_storage remote_addr_storage;
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr *>(&local_addr_storage);
    path.remote.addr = reinterpret_cast<sockaddr *>(&remote_addr_storage);

    // TODO: FIXME: flow control
    while (true) {
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        size_t vcnt = 0;
        int64_t stream_id = -1;

        int nwrite = ngtcp2_conn_writev_stream(conn_, &path, &pi, buf, 
            NGTCP2_MAX_PKTLEN_IPV4, &ndatalen, flags, stream_id, &vec, vcnt, srs_get_system_time());
        if (nwrite < 0) {
            return srs_error_new(ERROR_QUIC_CONN, "write stream failed");
        }

        if (nwrite == 0) {
            break;
        }

        if (nwrite > 0 && sendonly_skt_) {
            if ((err = sendonly_skt_->sendto(buf, nwrite, 0)) != srs_success) {
                return srs_error_wrap(err, "quic send packet failed");
            }

            srs_trace("ngtcp2_conn_writev_stream buf=%p, %d bytes", buf, nwrite);
        }
    }


    return err;
}
