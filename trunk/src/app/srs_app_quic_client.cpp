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

#include <srs_app_quic_client.hpp>

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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define SRS_TICKID_QUIC 1

const int kServerCidLen = 18;
const int kClientCidLen = 18;

static int cb_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
    const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) 
{
  	if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
    srs_trace("@john %s:%d", __func__, __LINE__);
  	  	return NGTCP2_ERR_CALLBACK_FAILURE;
  	}
  	return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
    return quic_conn->recv_stream_data(flags, stream_id, offset, data, datalen);
}

static int cb_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
    return quic_conn->recv_crypto_data(crypto_level, data, datalen);
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
    return quic_conn->handshake_completed();
}

static int cb_acked_crypto_offset(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, uint64_t datalen, void *user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
    return quic_conn->acked_crypto_offset(crypto_level, offset, datalen);
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data) 
{
    return 0;
}

static int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
  	return quic_conn->on_stream_open(stream_id);
}

static int cb_stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
    void *user_data, void *stream_user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
  	return quic_conn->on_stream_close(stream_id, app_error_code);
}

static int cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx,
    ngtcp2_rand_usage usage)
{
      return srs_generate_rand_data(dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
    size_t cidlen, void *user_data) 
{
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
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
    SrsQuicClient* quic_conn = static_cast<SrsQuicClient *>(user_data);
  	return quic_conn->update_key(rx_secret, tx_secret, rx_aead_ctx, rx_iv, 
        tx_aead_ctx, tx_iv, current_tx_secret, current_rx_secret, secretlen);
}

SrsQuicClient::SrsQuicClient()
{
    timer_ = new SrsHourGlass(this, 1 * SRS_UTIME_MILLISECONDS);
    udp_fd = NULL;

    conn_ = NULL;

    trd_ = NULL;

    tls_context_ = NULL;
    tls_session_ = NULL;
		quic_token_ = NULL;
}

SrsQuicClient::~SrsQuicClient()
{
    srs_freep(timer_);
    srs_close_stfd(udp_fd);

    srs_freep(trd_);

    srs_freep(tls_session_);
    srs_freep(quic_token_);
}

ngtcp2_path SrsQuicClient::build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
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

ngtcp2_callbacks SrsQuicClient::build_quic_callback()
{
}

ngtcp2_settings SrsQuicClient::build_quic_settings(uint8_t* token , size_t tokenlen, ngtcp2_cid original_dcid)
{
}

srs_error_t SrsQuicClient::create_udp_socket()
{
		srs_error_t err = srs_success;

		addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_NUMERICHOST;

    addrinfo* r  = NULL;
    SrsAutoFree(addrinfo, r);
    if(getaddrinfo(NULL, "0", (const addrinfo*)&hints, &r)) {
        return srs_error_new(ERROR_SYSTEM_IP_INVALID, "getaddrinfo hints=(%d,%d,%d)",
            hints.ai_family, hints.ai_socktype, hints.ai_flags);
    }

    int fd = 0;
    if ((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1) {
        return srs_error_new(ERROR_SOCKET_CREATE, "socket domain=%d, type=%d, protocol=%d",
            r->ai_family, r->ai_socktype, r->ai_protocol);
    }

		for (addrinfo* rp = r; rp; rp = rp->ai_next) {
    		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
    		  	break;
    		}
  	}

    local_addr_len_ = sizeof(local_addr_);
    if (getsockname(fd, (sockaddr*)&local_addr_, &local_addr_len_) != 0) {
        return srs_error_new(ERROR_SOCKET_CREATE, "get udp socket name failed");
    }

    srs_trace("local addrlen=%u, sa_family=%d, sin_port=%u", local_addr_len_, reinterpret_cast<sockaddr*>(&local_addr_)->sa_family,
        local_addr_.sin_port);

    udp_fd = srs_netfd_open_socket(fd);

	  return err;
}

srs_error_t SrsQuicClient::create_udp_io_thread()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("quic-client-io", this);

    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "coroutine");
    }

    return err;
}

srs_error_t SrsQuicClient::connect(const std::string& ip, uint16_t port)
{
    srs_error_t err = srs_success;

    tls_context_ = new SrsQuicTlsClientContext();
    if ((err = tls_context_->init("", "")) != srs_success) {
        return srs_error_wrap(err, "init quic tls client ctx failed");
    }

		quic_token_ = new SrsQuicToken();
    if ((err = quic_token_->init()) != srs_success) {
        return srs_error_wrap(err, "init quic token failed");
    }

    if ((err = create_udp_socket()) != srs_success) {
        return srs_error_wrap(err, "create socket failed");
    }

    if ((err = create_udp_io_thread()) != srs_success) {
        return srs_error_wrap(err, "create udp io thread failed");
    }

    remote_addr_len_ = sizeof(remote_addr_);
		remote_addr_.sin_family = AF_INET;
    remote_addr_.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &remote_addr_.sin_addr) != 1) {
        return srs_error_new(ERROR_QUIC_CLIENT, "invalid addr=%s", ip.c_str());
    }

    srs_trace("remote sa_family=%d, sin_port=%u", reinterpret_cast<sockaddr*>(&remote_addr_)->sa_family,
        remote_addr_.sin_port);

    if (true) {
        cb_.client_initial = ngtcp2_crypto_client_initial_cb;
        cb_.recv_client_initial = NULL;
        cb_.recv_crypto_data = cb_recv_crypto_data;
        cb_.handshake_completed = cb_handshake_completed;
        cb_.recv_version_negotiation = NULL;
        cb_.encrypt = ngtcp2_crypto_encrypt_cb;
        cb_.decrypt = ngtcp2_crypto_decrypt_cb;
        cb_.hp_mask = cb_hp_mask;
        cb_.recv_stream_data = cb_recv_stream_data;
        cb_.acked_crypto_offset = cb_acked_crypto_offset;
        cb_.acked_stream_data_offset = cb_acked_stream_data_offset;
        cb_.stream_open = NULL;
        cb_.stream_close = cb_stream_close;
        cb_.recv_stateless_reset = NULL;
        cb_.recv_retry = ngtcp2_crypto_recv_retry_cb;
        cb_.extend_max_local_streams_bidi = NULL;
        cb_.extend_max_local_streams_uni = NULL;
        cb_.rand = cb_rand;
        cb_.get_new_connection_id = cb_get_new_connection_id;
        cb_.remove_connection_id = NULL;
        cb_.update_key = cb_update_key;
        cb_.path_validation = cb_path_validation;
        cb_.select_preferred_addr = NULL;
        cb_.stream_reset = NULL;
        cb_.extend_max_remote_streams_bidi = NULL;
        cb_.extend_max_remote_streams_uni = NULL;
        cb_.extend_max_stream_data = cb_extend_max_stream_data;
        cb_.dcid_status = NULL;
        cb_.handshake_confirmed = NULL;
        cb_.recv_new_token = NULL;
        cb_.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cb_.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    }

    scid_.datalen = 17;
    srs_generate_rand_data(scid_.data, scid_.datalen);
    dcid_.datalen = kClientCidLen;
    srs_generate_rand_data(dcid_.data, dcid_.datalen);

    if (true) {
        ngtcp2_settings_default(&settings_);

        // TODO: FIXME: conf this values.
        settings_.log_printf = quic_log_printf;
		    settings_.initial_ts = srs_get_system_time();
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
  	    params.active_connection_id_limit = 7;
    }

    ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), 
        local_addr_len_, reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

    srs_trace("local addrlen=%u, sa_family=%d, sin_port=%u, sin_addr=%u", local_addr_len_, reinterpret_cast<sockaddr*>(&local_addr_)->sa_family,
        local_addr_.sin_port, *(uint32_t*)(&(local_addr_.sin_addr)));
    srs_trace("remote addrlen=%u, sa_family=%d, sin_port=%u, sin_addr=%u", remote_addr_len_, reinterpret_cast<sockaddr*>(&remote_addr_)->sa_family,
        remote_addr_.sin_port, *(uint32_t*)(&(remote_addr_.sin_addr)));

    int ret = ngtcp2_conn_client_new(&conn_, &dcid_, &scid_, &path,
        NGTCP2_PROTO_VER_MIN, &cb_, &settings_, NULL, this);

    if (ret != 0) {
				return srs_error_new(ERROR_QUIC_CONN, "new quic conn failed,ret=%d", ret);
    }

    tls_session_ = new SrsQuicTlsClientSession();
    if ((err = tls_session_->init(tls_context_, this)) != srs_success) {
        return srs_error_wrap(err, "tls session init failed");
    }

    ngtcp2_conn_set_tls_native_handle(conn_, tls_session_->get_ssl());

    // TODO: FIXME: need schecule
    if ((err = timer_->tick(SRS_TICKID_QUIC, 10 * SRS_UTIME_MILLISECONDS)) != srs_success) {
        return srs_error_wrap(err, "quic tick");
    }

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "timer start failed");
    }

    srs_trace("connect to %s:%u success", ip.c_str(), port);

    return err;
}

srs_error_t SrsQuicClient::on_data(const uint8_t* data, size_t size)
{
    srs_error_t err = srs_success;

    ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), 
        local_addr_len_, reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

    srs_trace("local sa_family=%d, sin_port=%u, sin_addr=%u", reinterpret_cast<sockaddr*>(&local_addr_)->sa_family,
        local_addr_.sin_port, *(uint32_t*)(&(local_addr_.sin_addr)));
    srs_trace("remote sa_family=%d, sin_port=%u, sin_addr=%u", reinterpret_cast<sockaddr*>(&remote_addr_)->sa_family,
        remote_addr_.sin_port, *(uint32_t*)(&(remote_addr_.sin_addr)));

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

    return try_to_write();
}

int SrsQuicClient::on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
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

int SrsQuicClient::on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
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

int SrsQuicClient::on_application_tx_key()
{
    return 0;
}

int SrsQuicClient::write_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen) 
{
    SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)level];
    crypto.data.push_back(string(reinterpret_cast<const char*>(data), datalen));

    string& buf = crypto.data.back();
    ngtcp2_conn_submit_crypto_data(conn_, level, reinterpret_cast<const uint8_t*>(buf.data()), buf.size());

    return 0;
}

int SrsQuicClient::acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen) 
{
  	SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)crypto_level];

    for (deque<string>& d = crypto.data; ! d.empty() && crypto.acked_offset + d.front().size() <= offset + datalen;) {
        string& v = d.front();
        crypto.acked_offset += v.size();
        d.pop_front();
    }
    return 0;
}

void SrsQuicClient::set_tls_alert(uint8_t alert)
{
    // TODO: FIXME:
}

int SrsQuicClient::recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, 
        const uint8_t *data, size_t datalen)
{
    srs_trace("stream %ld recv %u bytes", stream_id, datalen);
    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn_, datalen);

    return 0;
}

int SrsQuicClient::recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t* data, size_t datalen)
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

int SrsQuicClient::handshake_completed()
{
    srs_trace("quic handshake completed");

    return 0;
}

int SrsQuicClient::on_stream_open(int64_t stream_id)
{
		srs_trace("stream %ld open", stream_id);
    return 0;
}

int SrsQuicClient::on_stream_close(int64_t stream_id, uint64_t app_error_code)
{
		srs_trace("stream %ld close, app_error_code=%lu", stream_id, app_error_code);
    return 0;
}

int SrsQuicClient::get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen)
{
    cid->datalen = cidlen;
    srs_generate_rand_data(cid->data, cid->datalen);

    ngtcp2_crypto_md md = crypto_md_sha256();
    if (ngtcp2_crypto_generate_stateless_reset_token(token, &md, quic_token_->get_static_secret(), 
            quic_token_->get_static_secret_len(), cid) != 0) {
    srs_trace("@john %s:%d", __func__, __LINE__);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int SrsQuicClient::update_key(uint8_t *rx_secret, uint8_t *tx_secret,
        ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
        const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen) 
{
		uint8_t rx_key[64];
		uint8_t tx_key[64];

  	if (ngtcp2_crypto_update_key(conn_, rx_secret, tx_secret, rx_aead_ctx,
                               rx_key, rx_iv, tx_aead_ctx, tx_key,
                               tx_iv, current_rx_secret, current_tx_secret,
                               secretlen) != 0) {
    srs_trace("@john %s:%d", __func__, __LINE__);
        return NGTCP2_ERR_CALLBACK_FAILURE;
  	}

    return 0;
}

srs_error_t SrsQuicClient::notify(int type, srs_utime_t interval, srs_utime_t tick)
{
    return try_to_write();
}

srs_error_t SrsQuicClient::try_to_write()
{
    srs_error_t err = srs_success;

    srs_trace("@john %s:%d", __func__, __LINE__);

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
        srs_trace("@john, quic client write stream %d bytes", nwrite);
        if (nwrite < 0) {
            return srs_error_new(ERROR_QUIC_CONN, "write stream failed");
        }

        if (nwrite == 0) {
            break;
        }

        if (nwrite > 0 && udp_fd) {
            int ret = srs_sendto(udp_fd, buf, nwrite, reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_, 0);
            if (ret <= 0) {
                return srs_error_new(ERROR_QUIC_CONN, "quic send packet failed");
            }

            srs_trace("quic client client ngtcp2_conn_writev_stream buf=%p, %d bytes", buf, nwrite);
        }
    }

    return err;
}

srs_error_t SrsQuicClient::cycle()
{
   	srs_error_t err = srs_success;

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        uint8_t buf[1600];
        int nb_buf = sizeof(buf);
#if 0
				sockaddr_storage from;
        int nb_from = sizeof(from);
        int nread = srs_recvfrom(udp_fd, buf, nb_buf, (sockaddr*)&from, &nb_from, SRS_UTIME_NO_TIMEOUT);
        srs_trace("quic client recv %d bytes", nread);
        if (nread  <= 0) {
            return srs_error_new(ERROR_SOCKET_READ, "udp read, nread=%d", nread);
        }

        ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), 
            local_addr_len_, reinterpret_cast<sockaddr*>(&from), sizeof(from));

		    ngtcp2_pkt_info pkt_info;
		    int ret = ngtcp2_conn_read_pkt(conn_, &path, &pkt_info, buf, nread, srs_get_system_time());
		    if (ret != 0) {
            srs_error("ngtcp2_conn_read_pkt failed");
    		}
#else
        int nread = srs_recvfrom(udp_fd, buf, nb_buf, (sockaddr*)&remote_addr_, (int*)&remote_addr_len_, SRS_UTIME_NO_TIMEOUT);
        srs_trace("quic client recv %d bytes", nread);
        if (nread  <= 0) {
            return srs_error_new(ERROR_SOCKET_READ, "udp read, nread=%d", nread);
        }
        on_data(buf, nread);
#endif
		}

    return err;
}
