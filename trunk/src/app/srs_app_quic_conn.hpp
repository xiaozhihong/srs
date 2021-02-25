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
#include <srs_app_quic_transport.hpp>

#include <deque>
#include <string>
#include <map>
#include <vector>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>

class SrsQuicServer;
class SrsUdpMuxSocket;
class SrsQuicTlsServerSession;
class SrsQuicConnection;

// Connection event handler for QUIC.
class ISrsQuicConnHandler
{
public:
    ISrsQuicConnHandler() {}
    virtual ~ISrsQuicConnHandler() {}
public:
    virtual srs_error_t on_new_connection(SrsQuicConnection* conn) = 0;
    virtual srs_error_t on_connection_established(SrsQuicConnection* conn) = 0;
    virtual srs_error_t on_close(SrsQuicConnection* conn) = 0;
};

// Stream event handler for quic connection.
class ISrsQuicStreamHandler
{
public:
    ISrsQuicStreamHandler() {}
    virtual ~ISrsQuicStreamHandler() {}
public:
    virtual srs_error_t on_stream_open(SrsQuicConnection* conn, int64_t stream_id) = 0;
    virtual srs_error_t on_stream_close(SrsQuicConnection* conn, int64_t stream_id) = 0;
    virtual srs_error_t on_stream_data(SrsQuicConnection* conn, int64_t stream_id, const uint8_t* data, size_t datalen) = 0;
};

// Quic connection which accept from client.
class SrsQuicConnection : public SrsQuicTransport, virtual public ISrsResource
    , virtual public ISrsDisposingHandler
{
public:
    SrsQuicConnection(SrsQuicServer* s, const SrsContextId& cid);
  	~SrsQuicConnection();
public:
    srs_error_t accept(SrsUdpMuxSocket* skt, ngtcp2_pkt_hd* hd);
    srs_error_t on_udp_data(SrsUdpMuxSocket* skt, const uint8_t* data, int size);
public:
    void set_conn_handler(ISrsQuicConnHandler* conn_handler);
    void set_stream_handler(ISrsQuicStreamHandler* stream_handler);
// Interface SrsQuicTransport
private:
    virtual ngtcp2_settings build_quic_settings(uint8_t* token , size_t tokenlen, ngtcp2_cid* original_dcid);
	virtual uint8_t* get_static_secret();
    virtual size_t get_static_secret_len();
    virtual int recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
    virtual int handshake_completed();
    virtual srs_error_t init(sockaddr* local_addr, const socklen_t local_addrlen,
                sockaddr* remote_addr, const socklen_t remote_addrlen,
                ngtcp2_cid* scid, ngtcp2_cid* dcid, const uint32_t version,
                uint8_t* token, const size_t tokenlen);
public:
    virtual std::string get_connid();
public:
  	bool is_alive();
// Interface ISrsDisposingHandler
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

public:
    bool disposing_;
private:
    SrsContextId cid_;
    SrsQuicServer* server_;
    ISrsQuicConnHandler* conn_handler_;
    ISrsQuicStreamHandler* stream_handler_;
};

#endif
