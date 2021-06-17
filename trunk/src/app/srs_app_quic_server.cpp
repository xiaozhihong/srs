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

#include <srs_app_quic_server.hpp>

using namespace std;

#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_quic_conn.hpp>
#include <srs_app_quic_tls.hpp>
#include <srs_app_quic_util.hpp>
#include <srs_app_server.hpp>
#include <srs_service_utility.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_rtc_forward_quic_conn.hpp>

SrsQuicServer::SrsQuicServer()
{
    conn_manager_ = new SrsResourceManager("QUIC conn", true/*verbose*/);
}

SrsQuicServer::~SrsQuicServer()
{
    srs_freep(conn_manager_);
}

srs_error_t SrsQuicServer::initialize()
{
    srs_error_t err = srs_success;

    if ((err = conn_manager_->start()) != srs_success) {
        return srs_error_wrap(err, "start manager");
    }

    return err;
}

srs_error_t SrsQuicServer::on_quic_client(SrsQuicConnection* conn, SrsQuicListenerType type)
{
    srs_error_t err = srs_success;

    // Create QUIC application connections by listen type, the life of `conn` is manage by 
    // SrsQuicIoLoop, applicaion connections never free it.

    if (type == SrsQuicListenerRtcForward) {
        SrsRtcForwardQuicConn* rtc_forward_quic_conn = new SrsRtcForwardQuicConn(this, conn);
        conn_manager_->add(rtc_forward_quic_conn);
        if ((err = rtc_forward_quic_conn->start()) != srs_success) {
            srs_freep(rtc_forward_quic_conn);
            return srs_error_wrap(err, "quic rtc_forward_quic_conn start failed");
        }
    } else if (type == SrsQuicListenerHttpApi) {
        // TODO: FIXME:  HTTP3 support.
    } else if (type == SrsQuicListenerHttpStream) {
        // TODO: FIXME:  HTTP3 support.
    }


    return err;
}

void SrsQuicServer::remove(ISrsResource* resource)
{
    conn_manager_->remove(resource);
}

srs_error_t SrsQuicServer::listen()
{
    srs_error_t err = srs_success;

    if ((err = listen_http_api_quic()) != srs_success) {
        return srs_error_wrap(err, "listen http api quic failed");
    }

    if ((err = listen_http_stream_quic()) != srs_success) {
        return srs_error_wrap(err, "listen http stream quic failed");
    }

    if ((err = listen_rtc_server_quic()) != srs_success) {
        return srs_error_wrap(err, "listen rtc server quic failed");
    }

    return err;
}

srs_error_t SrsQuicServer::listen_http_api_quic()
{
    srs_error_t err = srs_success;

    if (! _srs_config->get_http_api_quic_enabled()) {
        return err;
    }

    std::string ep = _srs_config->get_http_api_quic_listen();

    std::string ip;
    int port;
    srs_parse_endpoint(ep, ip, port);

    SrsQuicListener* listener = new SrsQuicListener(this, SrsQuicListenerHttpApi);
    listeners_.push_back(listener);

    if ((err = listener->listen(ip, port)) != srs_success) {
        return srs_error_wrap(err, "listen quic %s:%u failed", ip.c_str(), port);
    }

    return err;
}

srs_error_t SrsQuicServer::listen_http_stream_quic()
{
    srs_error_t err = srs_success;

    if (! _srs_config->get_http_stream_quic_enabled()) {
        return err;
    }

    std::string ep = _srs_config->get_http_stream_quic_listen();

    std::string ip;
    int port;
    srs_parse_endpoint(ep, ip, port);

    SrsQuicListener* listener = new SrsQuicListener(this, SrsQuicListenerHttpStream);
    listeners_.push_back(listener);

    if ((err = listener->listen(ip, port)) != srs_success) {
        return srs_error_wrap(err, "listen quic %s:%u failed", ip.c_str(), port);
    }

    return err;
}

srs_error_t SrsQuicServer::listen_rtc_server_quic()
{
    srs_error_t err = srs_success;

    if (! _srs_config->get_rtc_server_quic_enabled()) {
        return err;
    }

    std::string ep = _srs_config->get_rtc_server_quic_listen();

    std::string ip;
    int port;
    srs_parse_endpoint(ep, ip, port);

    SrsQuicListener* listener = new SrsQuicListener(this, SrsQuicListenerRtcForward);
    listeners_.push_back(listener);

    if ((err = listener->listen(ip, port)) != srs_success) {
        return srs_error_wrap(err, "listen quic %s:%u failed", ip.c_str(), port);
    }

    return err;
}

SrsQuicServerAdapter::SrsQuicServerAdapter()
{
    quic_ = new SrsQuicServer();
}

SrsQuicServerAdapter::~SrsQuicServerAdapter()
{
    srs_freep(quic_);
}

srs_error_t SrsQuicServerAdapter::initialize()
{
    srs_error_t err = srs_success;

    if ((err = quic_->initialize()) != srs_success) {
        return srs_error_wrap(err, "quic server initialize");
    }

    return err;
}

srs_error_t SrsQuicServerAdapter::run()
{
    srs_error_t err = srs_success;

    if ((err = quic_->listen()) != srs_success) {
        return srs_error_wrap(err, "listen udp");
    }

    return err;
}

void SrsQuicServerAdapter::stop()
{
}
