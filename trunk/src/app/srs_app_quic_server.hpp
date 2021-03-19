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
#include <srs_app_quic_io_loop.hpp>

#include <string>

class SrsHourGlass;
class SrsQuicConnection;
class ISrsResource;
class SrsResourceManager;
class SrsQuicTlsServerContext;
class SrsQuicToken;
class SrsQuicListener;

// The QUIC server instance, manage QUIC connections.
class SrsQuicServer : public ISrsQuicHandler
{
public:
    SrsQuicServer();
    virtual ~SrsQuicServer();
// Interface for ISrsQuicHandler
public:
    virtual srs_error_t on_quic_client(SrsQuicConnection* conn, SrsQuicListenerType type);
    void remove(ISrsResource* resource);
public:
    srs_error_t initialize();
public:
    // TODO: FIXME: Support gracefully quit.
    // TODO: FIXME: Support reload.
    srs_error_t listen();
private:
    srs_error_t listen_http_api_quic();
    srs_error_t listen_http_stream_quic();
    srs_error_t listen_rtc_server_quic();
private:
    std::vector<SrsQuicListener*> listeners_;
    SrsResourceManager* conn_manager_;
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

#endif
