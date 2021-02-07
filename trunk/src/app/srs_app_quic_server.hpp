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

#ifndef SRS_APP_QUIC_SERVER_HPP
#define SRS_APP_QUIC_SERVER_HPP

#include <srs_core.hpp>

#include <srs_app_listener.hpp>
#include <srs_app_st.hpp>
#include <srs_app_reload.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_app_hybrid.hpp>

#include <string>

class SrsHourGlass;
class SrsQuicConnection;
class SrsResourceManager;
class SrsQuicTlsServerContext;
class SrsQuicToken;

// The QUIC server instance, listen UDP port, handle UDP packet, manage QUIC connections.
class SrsQuicServer : virtual public ISrsUdpMuxHandler, virtual public ISrsHourGlass
{
private:
    SrsHourGlass* timer_;
    struct sockaddr_in listen_sa_;
    std::vector<SrsUdpMuxListener*> listeners_;
    SrsQuicTlsServerContext* quic_tls_server_ctx_;
    SrsQuicToken* quic_token_;
public:
    SrsQuicServer();
    virtual ~SrsQuicServer();
public:
    sockaddr_in* local_addr() { return &listen_sa_; }
    socklen_t local_addrlen() { return sizeof(listen_sa_); }
    SrsQuicToken* get_quic_token() { return quic_token_; }
    SrsQuicTlsServerContext* get_quic_tls_server_ctx() { return quic_tls_server_ctx_; }
public:
    virtual srs_error_t initialize();
public:
    // TODO: FIXME: Support gracefully quit.
    // TODO: FIXME: Support reload.
    srs_error_t listen_udp();
    virtual srs_error_t on_udp_packet(SrsUdpMuxSocket* skt);
public:
    virtual srs_error_t notify(int type, srs_utime_t interval, srs_utime_t tick);
private:
    srs_error_t new_connection(SrsUdpMuxSocket* skt, SrsQuicConnection** p_conn);
    srs_error_t send_version_negotiation(SrsUdpMuxSocket* skt, const uint8_t version, 
        const uint8_t* dcid, const size_t dcid_len, const uint8_t* scid, const size_t scid_len);
};

// The QUIC server adapter.
class SrsQuicServerAdapter : public ISrsHybridServer
{
private:
    SrsQuicServer* quic_;
public:
    SrsQuicServerAdapter();
    virtual ~SrsQuicServerAdapter();
public:
    virtual srs_error_t initialize();
    virtual srs_error_t run();
    virtual void stop();
};

extern SrsResourceManager* _srs_quic_manager;

#endif
