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
#include <vector>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>

class SrsQuicTlsSession;
class SrsQuicStream;
class SrsQuicTransport;;

enum SrsQuicStreamDirection
{
    QuicStreamSendOnly = 1,
    QuicStreamRecvOnly = 2,
    QuicStreamSendRecv = 3,
};

// Quic stream buffer, use to store packet of stream to send.
class SrsQuicStreamBuffer
{
public:
    SrsQuicStreamBuffer(int64_t stream_id, const uint8_t* data, const size_t size);
    ~SrsQuicStreamBuffer();
public:
    bool empty() const;
    uint8_t* data();
    size_t size();
    void consumed(const size_t size);
    int64_t stream_id() const { return stream_id_; }
private:
    int64_t stream_id_;
    std::string buffer_;
};

// Stream event handler for quic connection.
class ISrsQuicStreamHandler
{
public:
    ISrsQuicStreamHandler() {}
    virtual ~ISrsQuicStreamHandler() {}
public:
    virtual srs_error_t on_new_stream(SrsQuicStream* stream) = 0;
};

enum SrsQuicError
{
    SrsQuicErrorSuccess = 0,
    SrsQuicErrorTimeout = 1,
    SrsQuicErrorIO = 2,
    SrsQuicErrorBadStream = 3,
    SrsQuicErrorEOF = 4,
};

class SrsQuicStream
{
    friend class SrsQuicTransport;
public:
    SrsQuicStream(int64_t stream_id, SrsQuicTransport* quic_transport);
    ~SrsQuicStream();

// API of SrsQuicStream
public:
    int write(const uint8_t* buf, size_t size, srs_utime_t timeout);
    int read(uint8_t* buf, size_t buf_size, srs_utime_t timeout);

    int64_t get_stream_id() const { return stream_id_; }
    SrsQuicError get_last_error() const { return last_err_; }
private:
    void on_open(SrsQuicTransport* transport);
    void on_close(SrsQuicTransport* transport);
private:
    void set_last_error(SrsQuicError err) { last_err_ = err; }
    srs_error_t on_recv_from_quic_transport(const uint8_t* buf, size_t size);
private:
    srs_cond_t ready_to_read_;
    std::deque<std::string> read_queue_;
    srs_cond_t ready_to_write_;
    std::deque<std::string> write_queue_;

    int64_t stream_id_;
    // Quic transport this stream belong, when transport closed, the pointer changed to NULL,
    // and all the operator(read/write) of this stream will return error.
    SrsQuicTransport* quic_transport_;
private:
    SrsQuicError last_err_;
};

// Quic transport base class, process quic packets.
class SrsQuicTransport : virtual public ISrsHourGlass
{
    friend class SrsQuicStream;
public:
    SrsQuicTransport();
  	virtual ~SrsQuicTransport();
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
    std::string get_conn_id();
    void set_stream_handler(ISrsQuicStreamHandler* stream_handler);
private:
    srs_error_t push_stream_data(int64_t stream_id, const uint8_t* data, size_t size);
private:
	srs_error_t update_rtt_timer();
    srs_error_t on_timer_quic_rexmit();
private:
    srs_error_t on_error();
    srs_error_t disconnect();
// interface ISrsHourGlass
protected:
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);
protected:
    virtual srs_error_t io_write_streams();
    srs_error_t send_connection_close();
    // Get static secret to generate quic token.
    virtual uint8_t* get_static_secret() = 0;
    virtual size_t get_static_secret_len() = 0;
    virtual int send_packet(ngtcp2_path* path, uint8_t* data, const int size);
// Quic tls callback function
public:
    int on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_application_tx_key();
    int write_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    int acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen);
    void set_tls_alert(uint8_t alert);
// Ngtcp2 callback function
public:
    virtual int handshake_completed() = 0;
    int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t* data, size_t datalen);
    int recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
	int on_stream_open(int64_t stream_id);
	int on_stream_close(int64_t stream_id, uint64_t app_error_code);
    int get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen);
    int update_key(uint8_t *rx_secret, uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
            ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv, const uint8_t *current_rx_secret,
            const uint8_t *current_tx_secret, size_t secretlen);
// SrsQuic API
public:
    // TODO: FIXME: add annotation.
    virtual srs_error_t open_stream(int64_t* stream_id, SrsQuicStream** stream);
    virtual srs_error_t close_stream(int64_t stream_id);

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
        std::deque<std::string> data;
        size_t acked_offset;
    } crypto_buffer_[3];

    SrsQuicTlsSession* tls_session_;
protected:
    std::string connection_close_packet_;
    std::deque<SrsQuicStreamBuffer> stream_send_queue_;
    std::map<int64_t, SrsQuicStream*> streams_;
    ISrsQuicStreamHandler* stream_handler_;
};

#endif
