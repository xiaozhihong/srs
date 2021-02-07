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

#ifndef SRS_APP_QUIC_CONN_HPP
#define SRS_APP_QUIC_CONN_HPP

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

class SrsQuicServer;
class SrsUdpMuxSocket;
class SrsQuicTlsServerSession;

class SrsQuicConnection : virtual public ISrsHourGlass, virtual public ISrsResource
    , virtual public ISrsDisposingHandler
{
public:
		bool disposing_;
private:
    SrsContextId cid_;
    SrsQuicServer* server_;
    SrsHourGlass* timer_;
    SrsUdpMuxSocket* sendonly_skt_;
private:
    ngtcp2_callbacks cb_;
    ngtcp2_settings settings_;
    ngtcp2_conn* conn_;
    ngtcp2_cid scid_;

private:
    struct SrsQuicCryptoBuffer {
        SrsQuicCryptoBuffer() : acked_offset(0) {}
        std::deque<std::string> data;
        size_t acked_offset;
    } crypto_buffer_[3];

    SrsQuicTlsServerSession* tls_server_session_;
public:
    SrsQuicConnection(SrsQuicServer* s, const SrsContextId& cid);
  	~SrsQuicConnection();
private:
    void update_sendonly_socket(SrsUdpMuxSocket* skt);
private:
    ngtcp2_path build_quic_path(sockaddr* local_addr, const socklen_t local_addrlen,
        sockaddr* remote_addr, const socklen_t remote_addrlen);
    ngtcp2_callbacks build_quic_callback();
    ngtcp2_settings build_quic_settings();
public:
  	bool is_alive();
    srs_error_t init(SrsUdpMuxSocket* skt, ngtcp2_pkt_hd* hd);
    srs_error_t on_data(SrsUdpMuxSocket* skt, const uint8_t* data, size_t size);
    ngtcp2_conn* conn() { return conn_; }
    std::string get_connid();
// interface ISrsDisposingHandler
public:
    virtual void on_before_dispose(ISrsResource* c);
    virtual void on_disposing(ISrsResource* c);
// Interface ISrsResource.
public:
    virtual const SrsContextId& get_id();
    virtual std::string desc();
public:
    void switch_to_context();
    const SrsContextId& context_id();
private:
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);
    srs_error_t try_to_write();
// quic tls callback function
public:
    int on_rx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_tx_key(ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
    int on_application_tx_key();
    int write_server_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen);
    int acked_crypto_offset(ngtcp2_crypto_level crypto_level, uint64_t offset, uint64_t datalen);
    void set_tls_alert(uint8_t alert);
// ngtcp2 callback function
public:
    int recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
    int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t* data, size_t datalen);
    int handshake_completed();
		int on_stream_open(int64_t stream_id);
		int on_stream_close(int64_t stream_id, uint64_t app_error_code);
    int get_new_connection_id(ngtcp2_cid *cid, uint8_t *token, size_t cidlen);
    int update_key(uint8_t *rx_secret, uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
            ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv, const uint8_t *current_rx_secret,
            const uint8_t *current_tx_secret, size_t secretlen);
};

#endif
