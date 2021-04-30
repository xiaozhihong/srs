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

#ifndef SRS_APP_QUIC_IO_LOOP_HPP
#define SRS_APP_QUIC_IO_LOOP_HPP

#include <srs_core.hpp>

#include <srs_app_listener.hpp>
#include <srs_app_st.hpp>
#include <srs_app_reload.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_app_hybrid.hpp>

#include <string>

class SrsQuicConnection;
class ISrsResource;
class SrsResourceManager;

enum SrsQuicListenerType
{
	// RTC server forward.
    SrsQuicListenerRtcForward = 0,
    SrsQuicListenerHttpApi = 1,
    SrsQuicListenerHttpStream = 2,
};

class ISrsQuicHandler
{
public:
    ISrsQuicHandler() {}
    virtual ~ISrsQuicHandler() {}
public:
    virtual srs_error_t on_quic_client(SrsQuicConnection* conn, SrsQuicListenerType type) = 0;
};

class SrsQuicListener : virtual public ISrsUdpMuxHandler
{
public:
    SrsQuicListener(ISrsQuicHandler* handler, SrsQuicListenerType type);
    ~SrsQuicListener();
public:
    srs_error_t listen(const std::string& ip, int port);
public:
    std::string get_key();
    std::string get_cert();
public:
    virtual srs_error_t on_udp_packet(SrsUdpMuxSocket* skt);
    srs_error_t on_accept_quic_conn(SrsQuicConnection* quic_conn);
    sockaddr_in* local_addr() { return &listen_sa_; }
    socklen_t local_addrlen() { return sizeof(listen_sa_); }
private:
    ISrsQuicHandler* handler_;
    SrsUdpMuxListener* listener_;
    SrsQuicListenerType listen_type_;
    struct sockaddr_in listen_sa_;
};

// The QUIC server instance, listen UDP port, handle UDP packet, manage QUIC connections.
class SrsQuicIoLoop
{
public:
    SrsQuicIoLoop();
    virtual ~SrsQuicIoLoop();
public:
    virtual srs_error_t initialize();
    void subscribe(SrsQuicConnection* quic_conn);
    void unsubscribe(SrsQuicConnection* quic_conn);
    void remove(ISrsResource* resource);
public:
    srs_error_t on_udp_packet(SrsUdpMuxSocket* skt, SrsQuicListener* listener);
private:
    srs_error_t new_connection(SrsUdpMuxSocket* skt, SrsQuicListener* listener, SrsQuicConnection** p_conn);
    srs_error_t send_version_negotiation(SrsUdpMuxSocket* skt, const uint8_t version, 
        const uint8_t* dcid, const size_t dcid_len, const uint8_t* scid, const size_t scid_len);
private:
    SrsResourceManager* quic_conn_map_;
};

extern SrsQuicIoLoop* _quic_io_loop;

#endif
