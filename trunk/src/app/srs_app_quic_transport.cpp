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

#include <srs_app_quic_transport.hpp>

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
#include <srs_app_quic_client.hpp>
#include <srs_service_utility.hpp>
#include <srs_service_st.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_tls.hpp>
#include <srs_app_quic_util.hpp>

#define SRS_TICKID_QUIC_REXMIT 	  2

const int kServerCidLen = 18;
const int kClientCidLen = 18;

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->recv_stream_data(flags, stream_id, offset, data, datalen);
}

static int cb_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->recv_crypto_data(crypto_level, data, datalen);
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->handshake_completed();
}

static int cb_acked_crypto_offset(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
    uint64_t offset, uint64_t datalen, void *user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->acked_crypto_offset(crypto_level, offset, datalen);
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data) 
{
    return 0;
}

static int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->on_stream_open(stream_id);
}

static int cb_stream_close(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
    void *user_data, void *stream_user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->on_stream_close(stream_id, app_error_code);
}

static int cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx,
    ngtcp2_rand_usage usage)
{
    return srs_generate_rand_data(dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
    size_t cidlen, void *user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->get_new_connection_id(cid, token, cidlen);
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
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->update_key(rx_secret, tx_secret, rx_aead_ctx, rx_iv, 
        tx_aead_ctx, tx_iv, current_tx_secret, current_rx_secret, secretlen);
}


SrsQuicStreamStatus::SrsQuicStreamStatus()
{
}

SrsQuicStreamStatus::~SrsQuicStreamStatus()
{
}

SrsQuicStreamBuffer::SrsQuicStreamBuffer(int64_t stream_id, const uint8_t* data, const size_t size)
    : stream_id_(stream_id)
    , buffer_(reinterpret_cast<const char*>(data), size)
{
}

SrsQuicStreamBuffer::~SrsQuicStreamBuffer()
{
}

bool SrsQuicStreamBuffer::empty() const
{
    return buffer_.empty();
}

uint8_t* SrsQuicStreamBuffer::data()
{
    return reinterpret_cast<uint8_t*>(const_cast<char*>(buffer_.data()));
}

size_t SrsQuicStreamBuffer::size()
{
    return buffer_.size();
}

void SrsQuicStreamBuffer::consumed(const size_t size)
{
    if (size > buffer_.size()) {
        buffer_.clear();
    } else {
        buffer_.erase(0, size);
    }
}

SrsQuicTransport::SrsQuicTransport()
{
    timer_ = new SrsHourGlass(this, 1 * SRS_UTIME_MILLISECONDS);
    conn_ = NULL;
    udp_fd_ = NULL;
    local_addr_len_ = 0;
    remote_addr_len_ = 0;
    tls_session_ = NULL;

    cb_.client_initial = ngtcp2_crypto_client_initial_cb;
    cb_.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb_.recv_crypto_data = cb_recv_crypto_data;
    cb_.handshake_completed = cb_handshake_completed;
    cb_.recv_version_negotiation = NULL;
    cb_.encrypt = ngtcp2_crypto_encrypt_cb;
    cb_.decrypt = ngtcp2_crypto_decrypt_cb;
    cb_.hp_mask = ngtcp2_crypto_hp_mask;
    cb_.recv_stream_data = cb_recv_stream_data;
    cb_.acked_crypto_offset = cb_acked_crypto_offset;
    cb_.acked_stream_data_offset = cb_acked_stream_data_offset;
    cb_.stream_open = cb_stream_open;
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
    cb_.stream_reset = cb_stream_reset;
    cb_.extend_max_remote_streams_bidi = cb_extend_max_remote_streams_bidi;
    cb_.extend_max_remote_streams_uni = NULL;
    cb_.extend_max_stream_data = cb_extend_max_stream_data;
    cb_.dcid_status = NULL;
    cb_.handshake_confirmed = NULL;
    cb_.recv_new_token = NULL;
    cb_.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb_.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
}

SrsQuicTransport::~SrsQuicTransport()
{
    srs_freep(timer_);
    srs_freep(tls_session_);

    if (conn_) {
        ngtcp2_conn_del(conn_);
    }
}

ngtcp2_path SrsQuicTransport::build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
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

srs_error_t SrsQuicTransport::init_timer()
{
    srs_error_t err = srs_success;

    if ((err = timer_->tick(SRS_TICKID_QUIC_REXMIT, 10 * SRS_UTIME_MILLISECONDS)) != srs_success) {
        return srs_error_wrap(err, "quic tick");
    }

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "timer start failed");
    }

    return err;
}

srs_error_t SrsQuicTransport::on_data(ngtcp2_path* path, const uint8_t* data, size_t size)
{
    srs_error_t err = srs_success;

    ngtcp2_pkt_info pkt_info;
    int ret = ngtcp2_conn_read_pkt(conn_, path, &pkt_info, data, size, srs_get_system_time());
    if (ret != 0) {
        switch (ret) {
          // TODO: FIXME: process case below.
            case NGTCP2_ERR_DRAINING:
                break;
            case NGTCP2_ERR_RETRY:
                break;
            case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
            case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
            case NGTCP2_ERR_TRANSPORT_PARAM:
            case NGTCP2_ERR_DROP_CONN:
            default: 
                srs_error("read data %ld failed, err=%s", ngtcp2_strerror(ret));
                return on_error();

        }
        return srs_error_new(ERROR_QUIC_DATA, "quic read packet failed,ret=%d", ret);
    }

    return io_write_streams();
}

std::string SrsQuicTransport::get_conn_id()
{
    if (conn_ == NULL) {
        return "";
    }

    return string(reinterpret_cast<const char*>(scid_.data), scid_.datalen);
}

srs_error_t SrsQuicTransport::update_rtt_timer()
{
    srs_error_t err = srs_success;

    if (conn_ == NULL) {
        return err;
    }

    // TODO: FIXME: time unit is ms or us?
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
    srs_utime_t now = srs_get_system_startup_time();

    int64_t delta = (expiry - now) / NGTCP2_SECONDS;
    // srs_trace("expiry=%lu, now=%lu, delta=%ld", expiry, now, delta);

    if ((err = timer_->tick(SRS_TICKID_QUIC_REXMIT, delta * SRS_UTIME_MILLISECONDS)) != srs_success) {
        return srs_error_wrap(err, "quic tick");
    }

    return err;
}

int SrsQuicTransport::on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
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

int SrsQuicTransport::on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen) 
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

int SrsQuicTransport::on_application_tx_key()
{
    return 0;
}

int SrsQuicTransport::write_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen) 
{
    SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)level];
    // Store data info crypto buffer.
    crypto.data.push_back(string(reinterpret_cast<const char*>(data), datalen));

    string& buf = crypto.data.back();
    ngtcp2_conn_submit_crypto_data(conn_, level, reinterpret_cast<const uint8_t*>(buf.data()), buf.size());

    return 0;
}

int SrsQuicTransport::acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen) 
{
    SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)crypto_level];

    // TODO:FIXME: maybe acked partial?
    for (deque<string>& d = crypto.data; ! d.empty() && crypto.acked_offset + d.front().size() <= offset + datalen;) {
        string& v = d.front();
        crypto.acked_offset += v.size();
        d.pop_front();
    }
    return 0;
}

void SrsQuicTransport::set_tls_alert(uint8_t alert)
{
    srs_warn("QUIC tls alert %d", (int)alert);
    // TODO: FIXME: call on_error function?
}

int SrsQuicTransport::recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t* data, size_t datalen)
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

int SrsQuicTransport::recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, 
        const uint8_t *data, size_t datalen)
{
    // Quic stream level flow control.
    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn_, datalen);

    return 0;
}

int SrsQuicTransport::on_stream_open(int64_t stream_id)
{
    srs_trace("stream %ld open", stream_id);
    return 0;
}

int SrsQuicTransport::on_stream_close(int64_t stream_id, uint64_t app_error_code)
{
    srs_trace("stream %ld close, app_error_code=%lu", stream_id, app_error_code);
    return 0;
}

int SrsQuicTransport::get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen)
{
    cid->datalen = cidlen;
    srs_generate_rand_data(cid->data, cid->datalen);

    ngtcp2_crypto_md md = crypto_md_sha256();
    if (ngtcp2_crypto_generate_stateless_reset_token(token, &md, get_static_secret(), 
            get_static_secret_len(), cid) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int SrsQuicTransport::update_key(uint8_t *rx_secret, uint8_t *tx_secret,
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

srs_error_t SrsQuicTransport::notify(int type, srs_utime_t interval, srs_utime_t tick)
{
    srs_error_t err = srs_success;
    if (type == SRS_TICKID_QUIC_REXMIT) {
        err = on_timer_quic_rexmit();
    } else {
        srs_warn("timer %d no process", type);
    }
    return err;
}

srs_error_t SrsQuicTransport::on_timer_quic_rexmit()
{
    ngtcp2_tstamp now = srs_get_system_startup_time();
    int ret = ngtcp2_conn_handle_expiry(conn_, now);
    if (ret != 0) {
        on_error();
        return srs_error_new(ERROR_QUIC_CONN, "ngtcp2_conn_handle_expiry failed, err=%s",
                             ngtcp2_strerror(ret));
    }

    return io_write_streams();
}

srs_error_t SrsQuicTransport::on_error()
{
    return disconnect();
}

srs_error_t SrsQuicTransport::disconnect()
{
    srs_error_t err = srs_success;

    if (! conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
        srs_trace("quic conn is closing");
        return err;
    }

    stream_buffer_queue_.clear();

    sockaddr_storage local_addr_storage;
    sockaddr_storage remote_addr_storage;
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr*>(&local_addr_storage);
    path.remote.addr = reinterpret_cast<sockaddr*>(&remote_addr_storage);
  	ngtcp2_pkt_info pi;

    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};

    // TODO: FIXME: add error_code enum.
	int error_code = 666;
    int nwrite = ngtcp2_conn_write_connection_close(conn_, &path, &pi, buf, sizeof(buf), 
                error_code, srs_get_system_time());

    // TODO: FIXME: need store close frame and retry send until success?
    if (nwrite < 0) {
        return srs_error_new(ERROR_QUIC_CONN, "write connection close failed");
    }

    if (send_packet(&path, buf, nwrite) <= 0) {
        return srs_error_new(ERROR_QUIC_CONN, "close quic connection failed");
    }

    stream_buffer_queue_.clear();

    return err;
}

srs_error_t SrsQuicTransport::io_write_streams()
{
    srs_error_t err = srs_success;

    if ((err = check_conn_status()) != srs_success) {
        return srs_error_wrap(err, "check quic conn status failed");
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
    bool stop_send_loop = false;
    while (! stop_send_loop) {
        
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        size_t vcnt = 0;
        int64_t stream_id = -1;

        if (! stream_buffer_queue_.empty() && ngtcp2_conn_get_max_data_left(conn_) >= stream_buffer_queue_.front().size()) {
            SrsQuicStreamBuffer& buffer = stream_buffer_queue_.front();
            stream_id = buffer.stream_id();
            vec.base = buffer.data();
            vec.len = buffer.size();
            vcnt = 1;
            // TODO: FIXME: when stream finish, need add flag below.
            // flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        int nwrite = ngtcp2_conn_writev_stream(conn_, &path, &pi, buf,
            NGTCP2_MAX_PKTLEN_IPV4, &ndatalen, flags, stream_id, &vec, vcnt, srs_get_system_time());

        if (nwrite < 0) {
            switch (nwrite) {
                // write failed becasue stream flow control.
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                    stop_send_loop = true;
                    continue;
                // write failed becasuse stream in half close(write direction).
                case NGTCP2_ERR_STREAM_SHUT_WR: {
                    stop_send_loop = true;
                    continue;
                }
                case NGTCP2_ERR_WRITE_MORE: {
                    SrsQuicStreamBuffer& buffer = stream_buffer_queue_.front();
                    buffer.consumed(ndatalen);
                    srs_trace("write stream %ld need more, buffer size=%u", stream_id, buffer.size());
                    if (buffer.empty()) {
                        stream_buffer_queue_.pop_front();
                    }
                    continue;
                }
                default: {
                    srs_error("write stream %ld failed, err=%s", stream_id,  ngtcp2_strerror(nwrite));
                    return on_error();
                }
            }
        }

        if (send_packet(&path, buf, nwrite) <= 0) {
            // TODO: FIXME: should return err?
            // srs_warn("send quic packet failed");
            break;
        }
    }

    return update_rtt_timer();
}

int SrsQuicTransport::send_packet(ngtcp2_path* path, uint8_t* data, const int size)
{
    if (! udp_fd_ || data == NULL || size <= 0) {
        return -1;
    }

    // TODO: FIXME: should add timeout param?
    return srs_sendto(udp_fd_, data, size, path->remote.addr, 
                      path->remote.addrlen, SRS_UTIME_NO_TIMEOUT);
}

srs_error_t SrsQuicTransport::check_conn_status()
{
    if (! conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
        return srs_error_new(ERROR_QUIC_CONN, "quic conn is closing");
    }

    return srs_success;
}

srs_error_t SrsQuicTransport::open_stream(int64_t* stream_id)
{
    srs_error_t err = srs_success;

    // We can't determine which stream_id to open, it's alloc by libngtcp2.
    int ret = ngtcp2_conn_open_bidi_stream(conn_, stream_id, this);
    if (ret != 0) {
        // open stream blocking means we reached limit of max_streams of bidi_stream.
        if (ret == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            return srs_error_new(ERROR_QUIC_STREAM, "open quic stream blocked");
        }
        else if (ret == NGTCP2_ERR_NOMEM) {
            return srs_error_new(ERROR_QUIC_STREAM, "open quic stream failed, out of memory");
        }
    }

    return err;
}

srs_error_t SrsQuicTransport::write_stream_data(const int64_t stream_id, const uint8_t* data, const size_t size)
{
    srs_error_t err = srs_success;

    if (data == NULL || size == 0) {
        return err;
    }

    if ((err = check_conn_status()) != srs_success) {
        return srs_error_wrap(err, "check quic conn status failed");
    }

    // TODO: FIXME: quic packet is received same as we send?

    // Split data into packet because UDP have max packet size.
    int offset = 0;
    int max_packet_size = NGTCP2_MAX_PKTLEN_IPV4;
    int nb_packets = 1 + (size - 1) / max_packet_size;

    for (int i = 0; i < nb_packets; ++i) {
        int packet_size = (int)size - offset;
        if (packet_size > max_packet_size) {
            packet_size = max_packet_size;
        }
        SrsQuicStreamBuffer stream_buffer(stream_id, data + offset, packet_size);
        stream_buffer_queue_.push_back(stream_buffer);
        offset += packet_size;
    }

    return io_write_streams();
}

srs_error_t SrsQuicTransport::read_stream_data(const int64_t stream_id, uint8_t* buf, const size_t buf_size, int* nb_read)
{
    return srs_success;
}
