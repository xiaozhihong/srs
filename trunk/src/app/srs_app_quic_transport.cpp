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
#include <srs_app_quic_client.hpp>
#include <srs_service_utility.hpp>
#include <srs_service_st.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_tls.hpp>
#include <srs_app_quic_util.hpp>

#define SRS_TICKID_QUIC_TRANSPORT_TIMER 1
#define SRS_TICKID_QUIC_IDLE_TIMER 2

const uint64_t kNgtcp2NoTimeout = UINT64_MAX;

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

SrsQuicStreamBuffer::SrsQuicStreamBuffer(int capacity)
{
    capacity_ = capacity;
    size_ = 0;
    buffer_ = new uint8_t[capacity_];
    write_pos_ = 0;
    read_pos_ = 0;
}

SrsQuicStreamBuffer::~SrsQuicStreamBuffer()
{
    srs_freepa(buffer_);
}

int SrsQuicStreamBuffer::write(const void* buf, int buf_size)
{
    if (size_ == capacity_) {
        srs_error("buffer full");
        return 0;
    }

    int size_write = 0;
    if (write_pos_ >= read_pos_) {
        size_write = srs_min(capacity_ - (write_pos_ - read_pos_), buf_size);
        int write_size_to_buffer_end = srs_min(capacity_ - write_pos_, size_write);
        memcpy(buffer_ + write_pos_, buf, write_size_to_buffer_end);

        int write_size_from_buffer_begin = size_write - write_size_to_buffer_end;
        if (write_size_from_buffer_begin > 0) {
            memcpy(buffer_, static_cast<const uint8_t*>(buf) + write_size_to_buffer_end, write_size_from_buffer_begin);
        }

        write_pos_ += size_write;
        write_pos_ %= capacity_;
    } else {
        size_write = srs_min(read_pos_ - write_pos_, buf_size);
        memcpy(buffer_ + write_pos_, buf, size_write);
        write_pos_ += size_write;
    }

    size_ += size_write;

    return size_write;
}

int SrsQuicStreamBuffer::read(void* buf, int buf_size)
{
    srs_assert(buf_size > 0);

    if (size_ == 0) {
        srs_error("buffer empty");
        return 0;
    }

    int size_read = 0;
    if (write_pos_ == read_pos_) {
        size_read = srs_min(size_, buf_size);
        if (buf) {
            memcpy(buf, buffer_ + read_pos_, size_read);
        }
        read_pos_ += size_read;
    } else if (write_pos_ > read_pos_) {
        size_read = srs_min((write_pos_ - read_pos_), buf_size);
        if (buf) {
            memcpy(buf, buffer_ + read_pos_, size_read);
        }
        read_pos_ += size_read;
    } else {
        int size_read_to_buffer_end = srs_min(capacity_ - read_pos_, buf_size);
        if (buf) {
            memcpy(buf, buffer_ + read_pos_, size_read_to_buffer_end);
        }

        int size_read_from_buffer_begin = srs_min(buf_size - size_read_to_buffer_end, write_pos_);
        if (size_read_from_buffer_begin && buf) {
            memcpy(static_cast<uint8_t*>(buf) + size_read_to_buffer_end, buffer_, size_read_from_buffer_begin);
        }

        size_read = size_read_to_buffer_end + size_read_from_buffer_begin;
        read_pos_ += size_read;
        read_pos_ %= capacity_;
    }

    size_ -= size_read;

    return size_read;
}

uint8_t* SrsQuicStreamBuffer::data() const
{
    return buffer_ + read_pos_;
}

size_t SrsQuicStreamBuffer::sequent_size() const
{
    if (size_ == 0) {
        return 0;
    }

    if (write_pos_ > read_pos_) {
        return write_pos_ - read_pos_;
    }

    return capacity_ - read_pos_;
}

int SrsQuicStreamBuffer::skip(int size)
{
    return read(NULL, size);
}

SrsQuicStream::SrsQuicStream(int64_t stream_id, const SrsQuicStreamDirection& direction, 
                             const SrsQuicStreamState& state, SrsQuicTransport* transport)
    : recv_buffer_(kStreamDataSize) // TODO: FIXME: adapt to quic stream setting
    , send_buffer_(kStreamDataSize) // TODO: FIXME: adapt to quic stream setting
    , stream_id_(stream_id)
    , quic_transport_(transport)
    , direction_(direction)
    , state_(state)
{
    ready_to_read_ = srs_cond_new();
    read_blocking_  = false;

    ready_to_write_ = srs_cond_new();
    write_blocking_ = false;
}

SrsQuicStream::~SrsQuicStream()
{
    srs_cond_destroy(ready_to_read_);
    srs_cond_destroy(ready_to_write_);
}

srs_error_t SrsQuicStream::write(const void* buf, int size, ssize_t* nb_write, srs_utime_t timeout)
{
    if (send_buffer_.full()) {
        if (wait_writeable(timeout) != 0) {
            return srs_error_new(ERROR_QUIC_TIMEOUT, "quic conn %s, write stream %ld timeout",
                quic_transport_->get_conn_name().c_str(), stream_id_);
        }
    }

    int nb = send_buffer_.write(buf, size);
    if (nb_write) {
        *nb_write = nb;
    }

    return srs_success;
}

srs_error_t SrsQuicStream::write_fully(const void* buf, int size, ssize_t* nb_write, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    int offset = 0;
    while (offset != size) {
        ssize_t nb = 0;
        if ((err = write(static_cast<const uint8_t*>(buf) + offset, size - offset, &nb, timeout)) != srs_success) {
            return srs_error_wrap(err, "write stream %ld failed", stream_id_);
        }

        offset += nb;
        if (nb_write) {
            *nb_write += nb;
        }
    }
    return err;
}

srs_error_t SrsQuicStream::read(void* buf, int buf_size, ssize_t* nb_read, srs_utime_t timeout)
{
    while (recv_buffer_.empty()) {
        if (wait_readable(timeout) != 0) {
            return srs_error_new(ERROR_QUIC_TIMEOUT, "read stream %ld timeout", stream_id_);
        }
    }

    int nb = recv_buffer_.read(buf, buf_size);
    if (nb_read) {
        *nb_read = nb;
    }

    return srs_success;
}

srs_error_t SrsQuicStream::read_fully(void* buf, int buf_size, ssize_t* nb_read, srs_utime_t timeout)
{
    srs_error_t err = srs_success;
    int offset = 0;
    while (offset != buf_size) {
        ssize_t nb = 0;
        if ((err = read((uint8_t*)buf + offset, buf_size - offset, &nb, timeout)) != srs_success) {
            return srs_error_wrap(err, "read stream %ld failed", stream_id_);
        }

        offset += nb;
        if (nb_read) {
            *nb_read += nb;
        }
    }

    return err;
}

int SrsQuicStream::on_data(const uint8_t* buf, size_t size)
{
    int nb = recv_buffer_.write(buf, size);
    notify_readable();

    return nb;
}

srs_error_t SrsQuicStream::flush()
{
    return quic_transport_->write_stream_data(stream_id_, &send_buffer_);
}

int SrsQuicStream::wait_writeable(srs_utime_t timeout)
{
    write_blocking_ = true;
    return srs_cond_timedwait(ready_to_write_, timeout);
}

int SrsQuicStream::notify_writeable()
{
    if (! write_blocking_) {
        return 0;
    }

    write_blocking_ = false;
    return srs_cond_signal(ready_to_write_);
}

int SrsQuicStream::wait_readable(srs_utime_t timeout)
{
    read_blocking_ = true;
    return srs_cond_timedwait(ready_to_read_, timeout);
}

int SrsQuicStream::notify_readable()
{
    if (! read_blocking_) {
        return 0;
    }

    read_blocking_ = false;
    return srs_cond_signal(ready_to_read_);
}

SrsQuicTransport::SrsQuicTransport()
{
    timer_ = new SrsDynamicTimer("quic", this, 1 * SRS_UTIME_MILLISECONDS);
    conn_ = NULL;
    udp_fd_ = NULL;
    local_addr_len_ = 0;
    remote_addr_len_ = 0;
    udp_send_buffer_size_ = NGTCP2_MAX_PKTLEN_IPV4;
    udp_send_buffer_ = new uint8_t[udp_send_buffer_size_];
    tls_context_ = NULL;
    tls_session_ = NULL;
    quic_token_ = NULL;
    draining_ = false;
    alive_ = true;
    accept_stream_cond_ = srs_cond_new();

    // Set ngtcp2 quic callback functions.
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

    for (std::map<int64_t, SrsQuicStream*>::iterator iter = streams_.begin(); 
            iter != streams_.end(); ++iter) {
        srs_freep(iter->second);
    }
}

void SrsQuicTransport::on_ngtcp2_log(const char* fmt, va_list ap)
{
    static char buf[64*1024];
    if (false) {
        // TODO: FIXME: config if we log ngtcp2 quic log
        vsnprintf(buf, sizeof(buf), fmt, ap);
        srs_trace("ngtcp2 quic log # %s", buf);
    }
}

void SrsQuicTransport::on_qlog(uint32_t flags, const void *data, size_t datalen) 
{
    if (false) {
        // TODO: FIXME: config if we log qlog
        srs_trace("quic_conn %s QLOG # %s", get_conn_name().c_str(), 
            string(reinterpret_cast<const char*>(data), datalen).c_str());
    }
}

// TODO: FIXME: use ngtcp2_conn_get_path instead.
ngtcp2_path SrsQuicTransport::build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
        sockaddr* remote_addr, const socklen_t remote_addrlen)
{
    ngtcp2_path path;
    path.local.addr = local_addr;
    path.local.addrlen = local_addrlen;
    path.remote.addr = remote_addr;
    path.remote.addrlen = remote_addrlen;
    path.user_data = NULL;

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
    srs_error_t err = srs_success;

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        return send_connection_close();
    }

    if (in_draininig() || ngtcp2_conn_is_in_draining_period(conn_)) {
        return err;
    }

    ngtcp2_pkt_info pkt_info;
    int ret = ngtcp2_conn_read_pkt(conn_, path, &pkt_info, data, size, srs_get_system_time_for_quic());
    if (ret != 0) {
        srs_error("quic conn %s read pkt failed, err=%s", get_conn_name().c_str(), ngtcp2_strerror(ret));
        switch (ret) {
            case NGTCP2_ERR_DRAINING:
                if ((err = enter_draining_period()) != srs_success) {
                    srs_warn("enter draining period failed, err=%s", srs_error_desc(err).c_str());
                    srs_freep(err);
                }
                return srs_error_new(ERROR_QUIC_DRAINING, "quic conn close wait");
            case NGTCP2_ERR_RETRY:
                return srs_error_new(ERROR_QUIC_RETRY, "quic retry");
            case NGTCP2_ERR_DROP_CONN:
                return srs_error_new(ERROR_QUIC_DROP_CONN, "drop quic conn");
            case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
            case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
            case NGTCP2_ERR_TRANSPORT_PARAM:
            default: 
                return on_error();
        }
    }

    if ((err = update_idle_timer()) != srs_success) {
        srs_warn("update idle timer failed, err=%s", srs_error_desc(err).c_str());
        srs_freep(err);
    }

    return write_data();
}

std::string SrsQuicTransport::get_scid()
{
    if (conn_ == NULL) {
        return "";
    }

    return string(reinterpret_cast<const char*>(scid_.data), scid_.datalen);
}

std::string SrsQuicTransport::get_dcid()
{
    if (conn_ == NULL) {
        return "";
    }

    return string(reinterpret_cast<const char*>(dcid_.data), dcid_.datalen);
}

std::string SrsQuicTransport::get_conn_name()
{
    return get_local_name() + ":" + get_remote_name();
}

std::string SrsQuicTransport::get_local_name()
{
    return quic_conn_id_dump(get_scid());
}

std::string SrsQuicTransport::get_remote_name()
{
    return quic_conn_id_dump(get_dcid());
}

srs_error_t SrsQuicTransport::update_transport_timer()
{
    srs_error_t err = srs_success;

    if (conn_ == NULL) {
        return err;
    }

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
    if (expiry == kNgtcp2NoTimeout) {
        return err;
    }

    timer_->tick(SRS_TICKID_QUIC_TRANSPORT_TIMER, expiry / SRS_UTIME_MILLISECONDS);

    return err;
}

srs_error_t SrsQuicTransport::update_idle_timer()
{
    srs_error_t err = srs_success;

    if (conn_ == NULL) {
        return err;
    }

    ngtcp2_tstamp expiry = ngtcp2_conn_get_idle_expiry(conn_);
    if (expiry == kNgtcp2NoTimeout) {
        return err;
    }

    timer_->tick(SRS_TICKID_QUIC_IDLE_TIMER, expiry / SRS_UTIME_MILLISECONDS);

    return err;
}

srs_error_t SrsQuicTransport::update_idle_timer_in_closing_or_draining()
{
    srs_error_t err = srs_success;

    ngtcp2_tstamp now = srs_get_system_time_for_quic();
    int64_t pto_timeout = ngtcp2_conn_get_pto(conn_) * 3 + now;
    timer_->tick(SRS_TICKID_QUIC_IDLE_TIMER, pto_timeout / SRS_UTIME_MILLISECONDS);

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
    // Store data into crypto buffer.
    crypto.queue.push_back(string(reinterpret_cast<const char*>(data), datalen));

    string& buf = crypto.queue.back();
    ngtcp2_conn_submit_crypto_data(conn_, level, reinterpret_cast<const uint8_t*>(buf.data()), buf.size());

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
    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return -1;
    }

    int nb = stream->on_data(data, datalen);
    if (nb <= 0) {
        srs_warn("quic conn %s stream %ld no room to store incoming packet",
            get_conn_name().c_str(), stream_id);
        return -1;
    }

    if (nb < (int)datalen) {
        srs_warn("quic conn %s stream %ld partial data ack", get_conn_name().c_str(), stream_id);
    }

    // Quic stream level flow control.
    ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, nb);
    ngtcp2_conn_extend_max_offset(conn_, nb);

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
    notify_stream_writeable(stream_id);
    return 0;
}

int SrsQuicTransport::on_stream_open(int64_t stream_id)
{
    srs_trace("quic conn %s stream %ld open", get_conn_name().c_str(), stream_id);

    SrsQuicStream* stream = find_stream(stream_id);
    if (stream != NULL) {
        if (stream->is_opened()) {
            srs_warn("quic conn %s stream %ld already opened", get_conn_name().c_str(), stream_id);
            return -1;
        }
        srs_freep(stream);
        streams_.erase(stream_id);
    }

    // New quic stream open.
    SrsQuicStreamDirection direction = (ngtcp2_is_bidi_stream(stream_id) != 0) ? 
        SrsQuicStreamDirectionSendRecv : SrsQuicStreamDirectionRecvOnly;
    SrsQuicStream* new_stream = new SrsQuicStream(stream_id, direction, SrsQuicStreamStateOpened, this);
    streams_.insert(make_pair(stream_id, new_stream));

    notify_accept_stream(stream_id);

    return 0;
}

int SrsQuicTransport::on_stream_close(int64_t stream_id, uint64_t app_error_code)
{
    srs_trace("quic conn %s stream %ld close, app_error_code=%lu", 
        get_conn_name().c_str(), stream_id, app_error_code);

    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return 0;
    }

    if (stream->is_closed()) {
        srs_warn("quic conn %s stream %ld ready closed", get_conn_name().c_str(), stream_id);
        srs_freep(stream);
        streams_.erase(stream_id);
        return 0;
    }

    if (stream->is_closing()) {
        srs_freep(stream);
        streams_.erase(stream_id);
    } else {
        stream->notify_readable();
        stream->set_closed();
    }
    
    return 0;
}

int SrsQuicTransport::on_stream_reset(int64_t stream_id, uint64_t final_size, uint64_t app_error_code)
{
    srs_trace("quic conn %s stream %ld reset, final_size=%lu, app_error_code=%lu", 
        get_conn_name().c_str(), stream_id, final_size, app_error_code);

    // TODO: FIXME: impl it.
    return 0;
}

int SrsQuicTransport::get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen)
{
    cid->datalen = cidlen;
    // TODO: FIXME: connid must no be conflicted.
    srs_generate_rand_data(cid->data, cid->datalen);
    srs_trace("generate new conn id %s", quic_conn_id_dump(cid->data, cid->datalen).c_str());

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
    return 0;
}

void SrsQuicTransport::notify_stream_writeable(int64_t stream_id)
{
    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return;
    }

    stream->notify_writeable();
}

int SrsQuicTransport::update_key(uint8_t *rx_secret, uint8_t *tx_secret,
                                 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, 
                                 ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                                 const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, 
                                 size_t secretlen) 
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

srs_error_t SrsQuicTransport::accept_stream(srs_utime_t timeout, int64_t& stream_id)
{
    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        return srs_error_new(ERROR_QUIC_CLOSING, "quic conn in closing state");
    }
    
    if (ngtcp2_conn_is_in_draining_period(conn_)) {
        return srs_error_new(ERROR_QUIC_DRAINING, "quic conn in draning state");
    }

    int ret = srs_cond_timedwait(accept_stream_cond_, timeout);
    if (ret != 0) {
        stream_id = -1;
        return srs_error_new(ERROR_QUIC_TIMEOUT, "quic accept stream timeout");
    }

    stream_id = wait_accept_streams_.front();
    wait_accept_streams_.pop_front();

    return 0;
}

srs_error_t SrsQuicTransport::notify(int type, srs_utime_t now_time)
{
    srs_error_t err = srs_success;
    if (type == SRS_TICKID_QUIC_TRANSPORT_TIMER) {
        err = on_transport_timer();
    } else if (type == SRS_TICKID_QUIC_IDLE_TIMER) {
        err = on_idle_timer();
    } else {
        srs_warn("timer %d no process", type);
    }
    return err;
}

srs_error_t SrsQuicTransport::write_data()
{
    srs_error_t err = srs_success;
    srs_assert(conn_);

    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        return srs_error_new(ERROR_QUIC_CLOSING, "quic conn in closing state");
    }

    if (ngtcp2_conn_is_in_draining_period(conn_)) {
        return srs_error_new(ERROR_QUIC_DRAINING, "quic conn in draining state");
    }

    if ((err = write_stream_data(-1, NULL)) != srs_success) {
        srs_freep(err);
    }
    for (std::map<int64_t, SrsQuicStream*>::iterator iter = streams_.begin(); 
            iter != streams_.end(); ++iter) {
        SrsQuicStream* stream = iter->second;
        if ((err = stream->flush()) != srs_success) {
            // srs_error("flush quic stream %ld failed, err=%s", iter->first, srs_error_desc(err).c_str());
            srs_freep(err);
        }
    }

    return update_transport_timer();
}

srs_error_t SrsQuicTransport::on_transport_timer()
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

    if ((err = write_data()) != srs_success) {
        return srs_error_wrap(err, "write protocol data failed");
    }

    return err;
}

srs_error_t SrsQuicTransport::on_idle_timer()
{
    srs_error_t err = srs_success;
    if (ngtcp2_conn_is_in_closing_period(conn_)) {
        alive_ = false;
        return err;
    }

    if (in_draininig() || ngtcp2_conn_is_in_draining_period(conn_)) {
        alive_ = false;
        return err;
    }

    return enter_draining_period();
}

srs_error_t SrsQuicTransport::on_error()
{
    srs_error_t err = srs_success;
    // TODO: FIXME: add error code
    if ((err = enter_closing_period(666)) != srs_success) {
        return srs_error_wrap(err, "enter closing period failed");
    }

    return send_connection_close();
}

srs_error_t SrsQuicTransport::enter_closing_period(int error_code)
{
    srs_error_t err = srs_success;

    if (! conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
        // Already in closing state, return directly.
        return err;
    }

    timer_->untick(SRS_TICKID_QUIC_TRANSPORT_TIMER);

    if ((err = update_idle_timer_in_closing_or_draining()) != srs_success) {
        srs_warn("update idle timer failed, err=%s", srs_error_desc(err).c_str());
        srs_freep(err);
    }

    uint8_t buf[NGTCP2_MAX_PKTLEN_IPV4] = {0};

    int nwrite = ngtcp2_conn_write_connection_close(conn_, NULL, NULL, buf, sizeof(buf), 
            error_code, srs_get_system_time_for_quic());

    if (nwrite < 0) {
        return srs_error_new(ERROR_QUIC_CONN, "generate quic close frame failed");
    }

    // Store quic close frame, retry until success.
    connection_close_packet_.assign(reinterpret_cast<const char*>(buf), nwrite);

    return err;
}

srs_error_t SrsQuicTransport::enter_draining_period()
{
    srs_error_t err = srs_success;

    draining_ = true;

    timer_->untick(SRS_TICKID_QUIC_TRANSPORT_TIMER);

    if ((err = update_idle_timer_in_closing_or_draining()) != srs_success) {
        srs_warn("update idle timer failed, err=%s", srs_error_desc(err).c_str());
        srs_freep(err);
    }

    return err;
}

srs_error_t SrsQuicTransport::write_stream_data(int64_t stream_id, SrsQuicStreamBuffer* buffer)
{
    srs_error_t err = srs_success;

    ngtcp2_ssize ndatalen = 0;

    sockaddr_storage local_addr_storage;
    sockaddr_storage remote_addr_storage;
    ngtcp2_path path;
    path.local.addr = reinterpret_cast<sockaddr *>(&local_addr_storage);
    path.remote.addr = reinterpret_cast<sockaddr *>(&remote_addr_storage);

    while (true) {
        // No more stream data to write.
        if (buffer && buffer->empty()) {
            break;
        }

        // Merge write, ngtcp2 will append multi small quic packet into one udp packet if possiblity.
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        if (buffer && ngtcp2_conn_get_max_data_left(conn_) < NGTCP2_MAX_PKTLEN_IPV4) {
            return srs_error_new(ERROR_QUIC_AGAIN, "no data left in quic conn");
        }

        const uint8_t* data = buffer ? buffer->data() : NULL;
        size_t size = buffer ? buffer->sequent_size() : 0;
        int nwrite = ngtcp2_conn_write_stream(conn_, &path, NULL, udp_send_buffer_, udp_send_buffer_size_, 
                                              &ndatalen, flags, stream_id, data, size,
                                              srs_get_system_time_for_quic());

        if (nwrite == 0) {
            return srs_error_new(ERROR_QUIC_AGAIN, "quic conn congested");
        }

        if (nwrite < 0) {
            switch (nwrite) {
                // Write failed becasue stream flow control.
                case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
                    return srs_error_new(ERROR_QUIC_AGAIN, "quic conn stream %ld block", stream_id);
                }
                // Write failed becasuse stream in half close(write direction).
                case NGTCP2_ERR_STREAM_SHUT_WR: {
                    return srs_error_new(ERROR_QUIC_CONN, "quic conn shutdown");
                }
                // Data has been cached, try merge write with next packet.
                case NGTCP2_ERR_WRITE_MORE: {
                    if (buffer) {
                        buffer->skip(ndatalen);
                    }
                    continue;
                }
                default: {
                    srs_error("quic conn %s write stream %ld failed, err=%s", 
                        get_conn_name().c_str(), stream_id, ngtcp2_strerror(nwrite));
                    srs_error_t err = on_error();
                    if (err != srs_success) {
                        srs_freep(err);
                    }

                    return srs_error_new(ERROR_QUIC_CONN, "quic conn unknown error");
                }
            }
        }

        if (ndatalen > 0) {
            if (buffer) {
                buffer->skip(ndatalen);
            }
        }

        if ((err = update_idle_timer()) != srs_success) {
            srs_warn("update idle timer failed, err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        // nwrite is the length of quic packet, include data and header, ndatalen is the length of data.
        if (send_packet(&path, udp_send_buffer_, nwrite) <= 0) {
            return srs_error_new(ERROR_QUIC_UDP_SEND, "quic conn send udp packet error");
        }
    }

    return err;
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
        return srs_error_new(ERROR_QUIC_UDP_SEND, "close quic connection failed");
    }

    // TODO: FIXME: Need to stop when timeout for N times, if peer is no alive.
    srs_trace("quic conn %s send close frame", get_conn_name().c_str());

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
            return srs_error_new(ERROR_QUIC_STREAM, "quic conn %s open stream blocked",
                get_conn_name().c_str());
        }
        else if (ret == NGTCP2_ERR_NOMEM) {
            return srs_error_new(ERROR_QUIC_STREAM, "quic conn %s open stream failed, out of memory",
                get_conn_name().c_str());
        }
    }

    SrsQuicStream* new_stream = new SrsQuicStream(*stream_id, SrsQuicStreamDirectionSendRecv, SrsQuicStreamStateOpened, this);
    streams_.insert(make_pair(*stream_id, new_stream));

    ngtcp2_conn_set_stream_user_data(conn_, *stream_id, (void*)new_stream);

    srs_trace("quic conn %s open stream %ld success", get_conn_name().c_str(), *stream_id);

    return err;
}

srs_error_t SrsQuicTransport::close_stream(int64_t stream_id, uint64_t app_error_code)
{
    srs_error_t err = srs_success;

    srs_trace("quic conn %s close stream %ld", get_conn_name().c_str(), stream_id);

    // TODO: FIXME send close stream packet (NGTCP2_STREAM_FLAGS_FIN)
    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return srs_error_new(ERROR_QUIC_STREAM, "no found stream %ld", stream_id);
    }

    if (stream->is_closing()) {
        return err;
    }

    if (stream->is_closed()) {
        srs_freep(stream);
        streams_.erase(stream_id);
        return err;
    }

    int ret = ngtcp2_conn_shutdown_stream(conn_, stream_id, app_error_code);
    if (ret < 0) {
        if (ret == NGTCP2_ERR_NOMEM) {
            return srs_error_new(ERROR_QUIC_STREAM, "quic conn %s close stream failed, out of memory",
                get_conn_name().c_str());
        } else if (ret == NGTCP2_ERR_STREAM_NOT_FOUND) {
            srs_freep(stream);
            streams_.erase(stream_id);
            return err;
        }
    }

    stream->set_closing();
    return err;
}

srs_error_t SrsQuicTransport::write(int64_t stream_id, const void* buf, int size, ssize_t* nb_write, srs_utime_t timeout)
{
    srs_error_t err = srs_success;
    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return srs_error_new(ERROR_QUIC_BAD_STREAM, "can not found quic stream %ld", stream_id);
    }

    if ((err = stream->write(buf, size, nb_write, timeout)) != srs_success) {
        return srs_error_wrap(err, "write stream %ld failed", stream_id);
    }

    return srs_success;
}

srs_error_t SrsQuicTransport::write_fully(int64_t stream_id, const void* buf, int size, ssize_t* nb_write, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return srs_error_new(ERROR_QUIC_BAD_STREAM, "can not found quic stream %ld", stream_id);
    }

    ssize_t nb = 0;
    if ((err = stream->write_fully(buf, size, &nb, timeout)) != srs_success) {
        return srs_error_wrap(err, "write stream %ld failed", stream_id);
    }

    if (nb != size) {
        return srs_error_new(ERROR_QUIC_WRITE, "write stream %ld failed", stream_id);
    }

    if (nb_write) {
        *nb_write = nb;
    }

    return srs_success;
}

srs_error_t SrsQuicTransport::read(int64_t stream_id, void* buf, int size, ssize_t* nb_read, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return srs_error_new(ERROR_QUIC_BAD_STREAM, "can not found quic stream %ld", stream_id);
    }

    if ((err = stream->read(buf, size, nb_read, timeout)) != srs_success) {
        return srs_error_wrap(err, "read stream %ld faled", stream_id);
    }

    return srs_success;
}

srs_error_t SrsQuicTransport::read_fully(int64_t stream_id, void* buf, int size, ssize_t* nb_read, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    SrsQuicStream* stream = find_stream(stream_id);
    if (stream == NULL) {
        return srs_error_new(ERROR_QUIC_BAD_STREAM, "can not found quic stream %ld", stream_id);
    }

    ssize_t nb = 0;
    if ((err = stream->read_fully(buf, size, &nb, timeout)) != srs_success) {
        return srs_error_wrap(err, "read stream %ld failed", stream_id);
    }

    if (nb != size) {
        return srs_error_new(ERROR_QUIC_READ, "read stream %ld failed", stream_id);
    }

    if (nb_read) {
        *nb_read = nb;
    }

    return srs_success;
}

SrsQuicStream* SrsQuicTransport::find_stream(int64_t stream_id)
{
    map<int64_t, SrsQuicStream*>::iterator iter = streams_.find(stream_id);
    if (iter == streams_.end()) {
        return NULL;
    }

    return iter->second;
}
