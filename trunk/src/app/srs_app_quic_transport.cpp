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

#define SRS_TICKID_QUIC_TIMER     1

const uint64_t kNgtcp2NoTimeout = UINT64_MAX;
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
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->acked_stream_data_offset(stream_id, offset, datalen);
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

static int cb_remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data)
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->remove_connection_id(cid);
}

static int cb_path_validation(ngtcp2_conn *conn, const ngtcp2_path *path,
        ngtcp2_path_validation_result res, void *user_data) 
{
    return 0;
}

static int cb_stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
    uint64_t app_error_code, void *user_data, void *stream_user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport *>(user_data);
    return quic_transport->on_stream_reset(stream_id, final_size, app_error_code);
}

static int cb_extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) 
{
    srs_warn("quic unprocess function %s", __func__);
    return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t max_data, void *user_data, void *stream_user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(user_data);
    return quic_transport->extend_max_stream_data(stream_id, max_data);
}

static int cb_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, 
    uint8_t *tx_iv, const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, 
    size_t secretlen, void *user_data) 
{
    SrsQuicTransport* quic_transport = static_cast<SrsQuicTransport*>(user_data);
    return quic_transport->update_key(rx_secret, tx_secret, rx_aead_ctx, rx_iv, 
        tx_aead_ctx, tx_iv, current_tx_secret, current_rx_secret, secretlen);
}

SrsQuicStream::SrsQuicStream(int64_t stream_id, SrsQuicTransport* transport)
    : stream_id_(stream_id)
    , quic_transport_(transport)
{
    ready_to_read_ = srs_cond_new();
    ready_to_write_ = srs_cond_new();
}

SrsQuicStream::~SrsQuicStream()
{
    srs_cond_destroy(ready_to_read_);
    srs_cond_destroy(ready_to_write_);
}

int SrsQuicStream::write(const void* buf, int size, srs_utime_t timeout)
{
    if (quic_transport_->check_send_flow_limit(stream_id_, size)) {
        if (wait_writeable(timeout) != 0) {
            quic_transport_->set_last_error(SrsQuicErrorTimeout);
            srs_error("write stream %ld timeout", stream_id_);
            return -1;
        }
    }

    if (quic_transport_->check_send_flow_limit(stream_id_, size)) {
        quic_transport_->set_last_error(SrsQuicErrorTimeout);
        srs_error("write stream %ld timeout after double check", stream_id_);
        return -1;
    }

    quic_transport_->add_to_buffer(stream_id_, buf, size);
    srs_error_t err = quic_transport_->write_stream_data(stream_id_);
    if (err != srs_success) {
        srs_warn("write stream data failed, err=%s", srs_error_desc(err).c_str());
    }

    return size;
}

int SrsQuicStream::read(void* buf, int buf_size, srs_utime_t timeout)
{
    while (read_buffer_.empty()) {
        if (wait_readable(timeout) != 0) {
            quic_transport_->set_last_error(SrsQuicErrorTimeout);
            return -1;
        }
    }

    int size = min(buf_size, (int)read_buffer_.size());
    memcpy(buf, read_buffer_.data(), size);
    read_buffer_.erase(0, size);

    return size;
}

int SrsQuicStream::read_fully(void* buf, int buf_size, srs_utime_t timeout)
{
    int offset = 0;
    while (offset != buf_size) {
        int read_size = buf_size - offset;
        int nb = read((uint8_t*)buf + offset, read_size, timeout);
        if (nb <= 0) {
            return -1;
        }

        offset += nb;
    }
    return offset;
}

srs_error_t SrsQuicStream::on_recv_from_quic_transport(const uint8_t* buf, size_t size)
{
    srs_error_t err = srs_success;

    read_buffer_.append(string(reinterpret_cast<const char*>(buf), size));
    notify_readable();

    return err;
}

int SrsQuicStream::wait_writeable(srs_utime_t timeout)
{
    quic_transport_->wait_stream_writeable(stream_id_);
    return srs_cond_timedwait(ready_to_write_, timeout);
}

int SrsQuicStream::notify_writeable()
{
    return srs_cond_signal(ready_to_write_);
}

int SrsQuicStream::wait_readable(srs_utime_t timeout)
{
    return srs_cond_timedwait(ready_to_read_, timeout);
}

int SrsQuicStream::notify_readable()
{
    return srs_cond_signal(ready_to_read_);
}

void SrsQuicStream::on_close(SrsQuicTransport* transport)
{
    // Notify st-thread which waiting read result.
    notify_readable();
}

SrsQuicTransport::SrsQuicTransport()
{
    timer_ = new SrsHourGlass("quic", this, 10 * SRS_UTIME_MILLISECONDS);
    conn_ = NULL;
    udp_fd_ = NULL;
    local_addr_len_ = 0;
    remote_addr_len_ = 0;
    tls_context_ = NULL;
    tls_session_ = NULL;
    quic_token_ = NULL;
    accept_stream_cond_ = srs_cond_new();

    blocking_ = false;

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
    cb_.remove_connection_id = cb_remove_connection_id;
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
    srs_freep(tls_context_);
    srs_freep(tls_session_);
    srs_freep(quic_token_);

    if (conn_) {
        ngtcp2_conn_del(conn_);
    }

    srs_cond_destroy(accept_stream_cond_);
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

    if ((err = timer_->start()) != srs_success) {
        return srs_error_wrap(err, "timer start failed");
    }

    return err;
}

srs_error_t SrsQuicTransport::on_data(ngtcp2_path* path, const uint8_t* data, size_t size)
{
    ngtcp2_pkt_info pkt_info;
    int ret = ngtcp2_conn_read_pkt(conn_, path, &pkt_info, data, size, srs_get_system_time_for_quic());
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

    return write_protocol_data();
}

std::string SrsQuicTransport::get_conn_id()
{
    if (conn_ == NULL) {
        return "";
    }

    return string(reinterpret_cast<const char*>(scid_.data), scid_.datalen);
}

std::string SrsQuicTransport::get_conn_name()
{
    return quic_conn_id_dump(get_conn_id());
}

void SrsQuicTransport::wait_stream_writeable(int64_t stream_id)
{
    stream_waiting_writeable_.insert(stream_id);
}

srs_error_t SrsQuicTransport::update_timer()
{
    srs_error_t err = srs_success;

    if (conn_ == NULL) {
        return err;
    }

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
    if (expiry == kNgtcp2NoTimeout) {
        return err;
    }

    ngtcp2_tstamp now = srs_get_system_time_for_quic();

    int64_t delta_ms = expiry < now ? 1 : (expiry - now) /  NGTCP2_MILLISECONDS;
    delta_ms = ((delta_ms - 1) / 10 + 1) * 10;
    if (delta_ms <= 0) {
        delta_ms = 10;
    }

    if ((err = timer_->tick(SRS_TICKID_QUIC_TIMER, delta_ms * SRS_UTIME_MILLISECONDS)) != srs_success) {
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
    crypto.queue.push_back(string(reinterpret_cast<const char*>(data), datalen));

    string& buf = crypto.queue.back();
    ngtcp2_conn_submit_crypto_data(conn_, level, reinterpret_cast<const uint8_t*>(buf.data()), buf.size());

    return 0;
}

int SrsQuicTransport::acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen) 
{
    SrsQuicCryptoBuffer& crypto = crypto_buffer_[(int)crypto_level];

    // TODO:FIXME: maybe acked partial?
    deque<string>& queue = crypto.queue;
    while (queue.empty() && crypto.acked_offset + queue.front().size() <= offset + datalen) {
        string& v = queue.front();
        crypto.acked_offset += v.size();
        queue.pop_front();
    }
    return 0;
}

int SrsQuicTransport::acked_stream_data_offset(int64_t stream_id, uint64_t offset, uint64_t datalen) 
{
    if (blocking_) {
        srs_trace("quic conn %s, streamid=%ld, acked offset=%u, datalen=%lu", get_conn_name().c_str(), stream_id, offset, datalen);
    }
    notify_stream_writeable(stream_id);
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

    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        return -1;
    }

    SrsQuicStream* stream = iter->second;
    srs_error_t err = stream->on_recv_from_quic_transport(data, datalen);
    if (err != srs_success) {
        srs_freep(err);
        return -1;
    }

    return 0;
}

int SrsQuicTransport::on_stream_open(int64_t stream_id)
{
    srs_trace("stream %ld open", stream_id);

    // New quic open from peer.
    SrsQuicStream* new_stream = new SrsQuicStream(stream_id, this);
    streams_.insert(make_pair(stream_id, new_stream));

    notify_accept_stream(stream_id);

    return 0;
}

int SrsQuicTransport::on_stream_close(int64_t stream_id, uint64_t app_error_code)
{
    srs_trace("stream %ld close, app_error_code=%lu", stream_id, app_error_code);

    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        return 0;
    }

    SrsQuicStream* stream = iter->second;
    stream->on_close(this);
    srs_freep(stream);
    streams_.erase(stream_id);

    return 0;
}

int SrsQuicTransport::on_stream_reset(int64_t stream_id, uint64_t final_size, uint64_t app_error_code)
{
    srs_trace("stream %ld reset, final_size=%lu, app_error_code=%lu", stream_id, final_size, app_error_code);
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

int SrsQuicTransport::remove_connection_id(const ngtcp2_cid *cid)
{
    // TODO: FIXME:
    srs_warn("remove quic connection id");
    return 0;
}

int SrsQuicTransport::extend_max_stream_data(int64_t stream_id, uint64_t max_data)
{
    if (blocking_) {
        srs_trace("quic conn %s, streamid=%ld, extend max_data=%lu", get_conn_name().c_str(), stream_id, max_data);
    }
    return 0;
}

void SrsQuicTransport::notify_stream_writeable(int64_t stream_id)
{
    set<int64_t>::iterator iter_wait = stream_waiting_writeable_.find(stream_id);
    if (iter_wait != stream_waiting_writeable_.end()) {
        map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
        if (iter != streams_.end()) {
            SrsQuicStream* stream = iter->second;
            stream->notify_writeable();
        }
        stream_waiting_writeable_.erase(iter_wait);
    }
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

void SrsQuicTransport::notify_accept_stream(int64_t stream_id)
{
    wait_accept_streams_.push_back(stream_id);
    srs_cond_signal(accept_stream_cond_);
}

int SrsQuicTransport::accept_stream(srs_utime_t timeout, int64_t& stream_id)
{
    int ret = srs_cond_timedwait(accept_stream_cond_, timeout);
    if (ret != 0) {
        set_last_error(SrsQuicErrorTimeout);
        stream_id = -1;
        return ret;
    }

    stream_id = wait_accept_streams_.front();
    wait_accept_streams_.pop_front();

    return 0;
}

srs_error_t SrsQuicTransport::notify(int type, srs_utime_t interval, srs_utime_t tick)
{
    srs_error_t err = srs_success;
    if (type == SRS_TICKID_QUIC_TIMER) {
        err = on_timer();
    } else {
        srs_warn("timer %d no process", type);
    }
    return err;
}

bool SrsQuicTransport::check_timeout()
{
    ngtcp2_tstamp timeout = ngtcp2_conn_get_idle_expiry(conn_);
    if (timeout == kNgtcp2NoTimeout) {
        return false;
    }

    ngtcp2_tstamp now = srs_get_system_time_for_quic();
    if (now > timeout) {
        return true;
    }

    return false;
}

srs_error_t SrsQuicTransport::write_protocol_data()
{
    srs_assert(conn_);

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        return send_connection_close();
    }

    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};
    ngtcp2_ssize ndatalen;

    ngtcp2_pkt_info pi;
    sockaddr_storage local_addr_storage;
    sockaddr_storage remote_addr_storage;
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr *>(&local_addr_storage);
    path.remote.addr = reinterpret_cast<sockaddr *>(&remote_addr_storage);

    while (true) {
        // Try append multi quic ctrl msg into one udp packet if possiblily.
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        // -1 means no stream data, it's quic control msg(ACK...)
        int64_t stream_id = -1;

        int nwrite = ngtcp2_conn_write_stream(conn_, &path, &pi, buf, NGTCP2_MAX_PKTLEN_IPV4, 
				&ndatalen, flags, stream_id, NULL, 0, srs_get_system_time_for_quic());

        if (nwrite < 0) {
            switch (nwrite) {
                // write failed becasue stream flow control.
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                    break;
                // write failed becasuse stream in half close(write direction).
                case NGTCP2_ERR_STREAM_SHUT_WR:
                    break;
                case NGTCP2_ERR_WRITE_MORE:
                    continue;
                default: {
                    srs_error("write stream %ld failed, err=%s", stream_id,  ngtcp2_strerror(nwrite));
                    return on_error();
                }
            }
        }

        if (nwrite == 0) {
            break;
        }

        if (send_packet(&path, buf, nwrite) <= 0) {
            break;
        }
    }

    return update_timer();
}

srs_error_t SrsQuicTransport::write_stream_data(int64_t stream_id)
{
    srs_assert(conn_);

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        return send_connection_close();
    }

    while (! send_buffer_.empty()) {
        int64_t stream_id = send_buffer_.front().first;
        string& data = send_buffer_.front().second;

        int nb_write = 0;
        int ret = write_stream(stream_id, data.data(), data.size(), nb_write);
        if (ret < 0) {
            return srs_success;
        }

        if (nb_write == static_cast<int>(data.size())) {
            send_buffer_.pop_front();
        } else {
            data.erase(0, nb_write);
        }
    }

    return srs_success;
}

srs_error_t SrsQuicTransport::on_timer()
{
    srs_error_t err = srs_success;
    ngtcp2_tstamp now = srs_get_system_time_for_quic();
    int ret = ngtcp2_conn_handle_expiry(conn_, now);
    if (ret != 0) {
        err = on_error();
        if (err != srs_success) {
            srs_freep(err);
        }
        return srs_error_new(ERROR_QUIC_CONN, "ngtcp2_conn_handle_expiry failed, err=%s",
                             ngtcp2_strerror(ret));
    }

    if (check_timeout()) {
        return on_error();
    }

    if ((err = write_protocol_data()) != srs_success) {
        return srs_error_wrap(err, "write protocol data failed");
    }

    return err;
}

srs_error_t SrsQuicTransport::on_error()
{
    return disconnect();
}

srs_error_t SrsQuicTransport::disconnect()
{
    srs_error_t err = srs_success;

    if (! conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
        return err;
    }

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
                error_code, srs_get_system_time_for_quic());

    if (nwrite < 0) {
        return srs_error_new(ERROR_QUIC_CONN, "write connection close failed");
    }

    // Store quic close frame, retry until success.
    connection_close_packet_.assign(reinterpret_cast<const char*>(buf), nwrite);

    if (send_packet(&path, buf, nwrite) <= 0) {
        return srs_error_new(ERROR_QUIC_CONN, "close quic connection failed");
    }

    return err;
}

int SrsQuicTransport::write_stream(const int64_t stream_id, const void* data, int len, int& nb_write)
{
    nb_write = 0;
    clear_last_error();
    if (conn_ == NULL) {
        set_last_error(SrsQuicErrorBadStream);
        return -1;
    }

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        srs_error_t err = send_connection_close();
        if (err != srs_success) {
            srs_warn("send closing failed, err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        set_last_error(SrsQuicErrorIO);
        return -1;
    }

    const int buf_size = NGTCP2_MAX_PKTLEN_IPV4;
    uint8_t buf[buf_size];
    ngtcp2_ssize ndatalen = 0;

    sockaddr_storage local_addr_storage;
    sockaddr_storage remote_addr_storage;
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr *>(&local_addr_storage);
    path.remote.addr = reinterpret_cast<sockaddr *>(&remote_addr_storage);

    while (true) {
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;

        if (ngtcp2_conn_get_max_data_left(conn_) < buf_size) {
            set_last_error(SrsQuicErrorAgain);
            return -1;
        }

        int nwrite = ngtcp2_conn_write_stream(conn_, &path, NULL, buf, buf_size, 
                &ndatalen, flags, stream_id, (uint8_t*)data + nb_write, len - nb_write, srs_get_system_time_for_quic());

        if (nwrite == 0) {
            set_last_error(SrsQuicErrorAgain);
            return -1;
        }

        if (nwrite < 0) {
            switch (nwrite) {
                // write failed becasue stream flow control.
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                    set_last_error(SrsQuicErrorAgain);
                    return -1;
                // write failed becasuse stream in half close(write direction).
                case NGTCP2_ERR_STREAM_SHUT_WR: {
                    set_last_error(SrsQuicErrorIO);
                    return -1;
                }
                default: {
                    srs_error("write stream %ld failed, err=%s", stream_id,  ngtcp2_strerror(nwrite));
                    srs_error_t err = on_error();
                    if (err != srs_success) {
                        srs_freep(err);
                    }

                    set_last_error(SrsQuicErrorIO);
                    return -1;
                }
            }
        }

        // nwrite is the length of quic packet, include data and header
        // ndatalen is the length of data.
        nb_write += ndatalen;
        if (send_packet(&path, buf, nwrite) <= 0) {
            set_last_error(SrsQuicErrorIO);
            return -1;
        }

        if (nb_write >= len) {
            break;
        }
    }

    return nb_write;
}

bool SrsQuicTransport::check_send_flow_limit(int64_t stream_id, int len)
{
    // TODO: FIXME:
    return send_buffer_.size() >= 10 * 1024 * 1024 / NGTCP2_MAX_PKTLEN_IPV4;
}

void SrsQuicTransport::add_to_buffer(const int64_t stream_id, const void* data, int len)
{
    send_buffer_.push_back(make_pair(stream_id, string((const char*)data, len)));
}

srs_error_t SrsQuicTransport::send_connection_close()
{
    srs_error_t err = srs_success;

    if (connection_close_packet_.empty()) {
        return srs_error_new(ERROR_QUIC_CONN, "empty connection close packet");
    }

    ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_),
        local_addr_len_, reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

    if (send_packet(&path, (uint8_t*)connection_close_packet_.data(), 
                     connection_close_packet_.size()) <= 0) {
        return srs_error_new(ERROR_QUIC_CONN, "close quic connection failed");
    }

    // TODO: FIXME: need to timeout for N timeout, if peer is no alive.

    return err;
}

uint8_t* SrsQuicTransport::get_static_secret()
{
    return quic_token_->get_static_secret();
}

size_t SrsQuicTransport::get_static_secret_len()
{
    return quic_token_->get_static_secret_len();
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

    SrsQuicStream* new_stream = new SrsQuicStream(*stream_id, this);
    streams_.insert(make_pair(*stream_id, new_stream));

    srs_trace("open stream %ld success", *stream_id);

    return err;
}

srs_error_t SrsQuicTransport::close_stream(int64_t stream_id)
{
    srs_error_t err = srs_success;

    srs_trace("close stream %ld", stream_id);

    // TODO: FIXME send close stream packet (NGTCP2_STREAM_FLAGS_FIN)
    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        return srs_error_new(ERROR_QUIC_STREAM, "no found stream %ld", stream_id);
    }

    // TODO: FIXME: enum app error code.
    uint64_t app_error_code = 666;
    int ret = ngtcp2_conn_shutdown_stream(conn_, stream_id, app_error_code);
    if (ret != 0) {
        // Log and ignore return value.
        srs_warn("close stream %ld failed, err=%s", stream_id, ngtcp2_strerror(ret));
    }

    SrsQuicStream* stream = iter->second;
    srs_freep(stream);
    streams_.erase(stream_id);

    return err;
}

int SrsQuicTransport::write(int64_t stream_id, const void* buf, int size, srs_utime_t timeout)
{
    clear_last_error();

    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        set_last_error(SrsQuicErrorBadStream);
        return -1;
    }

    SrsQuicStream* stream = iter->second;

    return stream->write(buf, size, timeout);
}

int SrsQuicTransport::read(int64_t stream_id, void* buf, int size, srs_utime_t timeout)
{
    clear_last_error();

    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        set_last_error(SrsQuicErrorBadStream);
        return -1;
    }

    SrsQuicStream* stream = iter->second;
    return stream->read(buf, size, timeout);
}

int SrsQuicTransport::read_fully(int64_t stream_id, void* buf, int size, srs_utime_t timeout)
{
    clear_last_error();

    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        set_last_error(SrsQuicErrorBadStream);
        return -1;
    }

    SrsQuicStream* stream = iter->second;
    return stream->read_fully(buf, size, timeout);
}
