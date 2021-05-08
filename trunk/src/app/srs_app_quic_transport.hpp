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

#ifndef SRS_APP_QUIC_TRANSPORT_HPP
#define SRS_APP_QUIC_TRANSPORT_HPP

#include <srs_core.hpp>
#include <srs_app_listener.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_service_st.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_reload.hpp>
#include <srs_service_conn.hpp>
#include <srs_app_conn.hpp>

#include <deque>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>

class SrsQuicTlsContext;
class SrsQuicTlsSession;
class SrsQuicToken;
class SrsQuicStream;
class SrsQuicTransport;

enum SrsQuicStreamDirection
{
    SrsQuicStreamDirectionSendOnly = 1,
    SrsQuicStreamDirectionRecvOnly = 2,
    SrsQuicStreamDirectionSendRecv = 3,
};

enum SrsQuicError
{
    SrsQuicErrorSuccess = 0,
    SrsQuicErrorTimeout = 1,
    SrsQuicErrorIO = 2,
    SrsQuicErrorBadStream = 3,
    SrsQuicErrorEOF = 4,
    SrsQuicErrorAgain = 5,
    SrsQuicErrorClose = 6,
};

enum SrsQuicStreamState
{
    SrsQuicStreamStateOpening = 1,
    SrsQuicStreamStateOpened = 2,
    SrsQuicStreamStateClosing = 3,
    SrsQuicStreamStateClosed = 4,
};

// Ring buffer with fixed size, avoid alloc/free memoyy multi times.
class SrsQuicStreamBuffer
{
public:
    SrsQuicStreamBuffer(int size);
    ~SrsQuicStreamBuffer();
public:
    int write(const void* data, int size);
    int read(void* data, int size);
    uint8_t* data() const;
    size_t sequent_size() const;
    int skip(int size);
    size_t size() const { return static_cast<size_t>(size_); }
    bool empty() const { return size_ == 0; }
private:
    int capacity_;
    int size_;
    uint8_t* buffer_;
    int write_pos_;
    int read_pos_;
};

class SrsQuicStream
{
public:
    SrsQuicStream(int64_t stream_id, const SrsQuicStreamDirection& direction, 
                  const SrsQuicStreamState& state, SrsQuicTransport* quic_transport);
    ~SrsQuicStream();
public:
    int write(const void* buf, int size, srs_utime_t timeout);
    int write_fully(const void* buf, int size, srs_utime_t timeout);
    int read(void* buf, int buf_size, srs_utime_t timeout);
    int read_fully(void* buf, int buf_size, srs_utime_t timeout);
public:
    int wait_writeable(srs_utime_t timeout);
    int notify_writeable();
    int wait_readable(srs_utime_t timeout);
    int notify_readable();
    int on_data(const uint8_t* buf, size_t size);
public:
    bool is_opening() const { return state_ == SrsQuicStreamStateOpening; }
    bool is_opened() const { return state_ == SrsQuicStreamStateOpened; }
    bool is_closing() const { return state_ == SrsQuicStreamStateClosing; }
    bool is_closed() const { return state_ == SrsQuicStreamStateClosed; }
    void set_closing() { state_ = SrsQuicStreamStateClosing; }
    void set_closed() { state_ = SrsQuicStreamStateClosed; }
private:
    SrsQuicStreamBuffer recv_buffer_;
    srs_cond_t ready_to_read_;
    bool read_blocking_;

    SrsQuicStreamBuffer send_buffer_;
    srs_cond_t ready_to_write_;
    bool write_blocking_;

    int64_t stream_id_;
    SrsQuicTransport* quic_transport_;
private:
    SrsQuicStreamDirection direction_;
    SrsQuicStreamState state_;
};

// Quic transport base class, process quic packets.
class SrsQuicTransport : virtual public ISrsHourGlass
{
friend class SrsQuicStream;
public:
    SrsQuicTransport();
  	virtual ~SrsQuicTransport();
public:
    void on_ngtcp2_log(const char* fmt, va_list ap);
    void on_qlog(uint32_t flags, const void *data, size_t datalen);
protected:
    // Helper function to buid struct ngtcp2_path.
    ngtcp2_path build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
                                sockaddr* remote_addr, const socklen_t remote_addrlen);
    // Helper function to build quic settings, client/server role have different settings.
    virtual ngtcp2_settings build_quic_settings(uint8_t* token, size_t tokenlen, ngtcp2_cid* original_dcid) = 0;
public:
    virtual srs_error_t init_timer();
	virtual srs_error_t init(sockaddr* local_addr, const socklen_t local_addrlen,
                             sockaddr* remote_addr, const socklen_t remote_addrlen,
                             ngtcp2_cid* scid, ngtcp2_cid* dcid, const uint32_t version,
                             uint8_t* token, const size_t tokenle) = 0;

    srs_error_t on_data(ngtcp2_path* path, const uint8_t* data, size_t size);
    ngtcp2_conn* conn() { return conn_; }
    std::string get_scid();
    std::string get_dcid();
    std::string get_conn_name();
    std::string get_local_name();
    std::string get_remote_name();
    void wait_stream_writeable(int64_t stream_id);
    SrsQuicError get_last_error() const { return last_err_; }
    void set_last_error(SrsQuicError err) { last_err_ = err; }
    void set_blocking(bool b) { blocking_ = b; }
    bool is_blocking() const { return blocking_; }
private:
    void clear_last_error() { last_err_ = SrsQuicErrorSuccess; }
    int write_stream_data(int64_t stream_id, SrsQuicStreamBuffer& buffer);
private:
	srs_error_t update_timer();
    srs_error_t on_timer();
private:
    srs_error_t on_error();
    srs_error_t disconnect();

    void notify_accept_stream(int64_t stream_id);
    void notify_stream_writeable(int64_t stream_id);
// interface ISrsHourGlass
protected:
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);
protected:
    bool check_timeout();
    srs_error_t write_protocol_data();
    srs_error_t send_connection_close();
    // Get static secret to generate quic token.
    uint8_t* get_static_secret();
    size_t get_static_secret_len();
    virtual int send_packet(ngtcp2_path* path, uint8_t* data, const int size);
// Quic tls callback function
public:
    int on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_application_tx_key();
    int write_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    void set_tls_alert(uint8_t alert);
// Ngtcp2 callback function
public:
    virtual int handshake_completed() = 0;
    int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t* data, size_t datalen);
    int recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
    int acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen);
    int acked_stream_data_offset(int64_t stream_id, uint64_t offset, uint64_t datalen);
	int on_stream_open(int64_t stream_id);
	int on_stream_close(int64_t stream_id, uint64_t app_error_code);
    int on_stream_reset(int64_t stream_id, uint64_t final_size, uint64_t app_error_code);
    int get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen);
    int remove_connection_id(const ngtcp2_cid *cid);
    int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
    int update_key(uint8_t *rx_secret, uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                   ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv, const uint8_t *current_rx_secret,
                   const uint8_t *current_tx_secret, size_t secretlen);
// SrsQuic API
public:
    // TODO: FIXME: add annotation.
    virtual srs_error_t open_stream(int64_t* stream_id);
    virtual srs_error_t close_stream(int64_t stream_id, uint64_t app_error_code);
    int accept_stream(srs_utime_t timeout, int64_t& stream_id);
    int write(int64_t stream_id, const void* buf, int size, srs_utime_t timeout);
    int read(int64_t stream_id, void* buf, int size, srs_utime_t timeout);
    int read_fully(int64_t stream_id, void* buf, int size, srs_utime_t timeout);

private:
    SrsQuicStream* find_stream(int64_t stream_id);

protected:
    void open_qlog_file(const std::string& conn_id);

protected:
    SrsHourGlass* timer_;
protected:
    ngtcp2_callbacks cb_;
    ngtcp2_settings settings_;
    ngtcp2_conn* conn_;
    ngtcp2_cid scid_;
    ngtcp2_cid dcid_;
    ngtcp2_cid origin_dcid_;
protected:
	srs_netfd_t udp_fd_;
    // Store quic connectoin addr, maybe update when connection migrate.
    sockaddr_in local_addr_;
    socklen_t local_addr_len_;
    sockaddr_in remote_addr_;
    socklen_t remote_addr_len_;
protected:
    // Struct to store quic crypto data(TLS handshake).
    struct SrsQuicCryptoBuffer {
        SrsQuicCryptoBuffer() : acked_offset(0) {}
        int acked_offset;
        std::deque<std::string> queue;
    } crypto_buffer_[3];

    SrsQuicTlsContext* tls_context_;
    SrsQuicTlsSession* tls_session_;
    SrsQuicToken* quic_token_;
protected:
    std::string connection_close_packet_;
    std::map<int64_t, SrsQuicStream*> streams_;
    SrsQuicError last_err_;
    srs_cond_t accept_stream_cond_;
    std::deque<int64_t> wait_accept_streams_;
private:
    bool blocking_;
};

#endif
