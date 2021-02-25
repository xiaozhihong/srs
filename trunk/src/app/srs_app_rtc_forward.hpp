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

#ifndef SRS_APP_RTC_FORWARD_HPP
#define SRS_APP_RTC_FORWARD_HPP

#include <srs_core.hpp>
#include <srs_app_listener.hpp>
#include <srs_service_st.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_app_hybrid.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_app_rtc_sdp.hpp>
#include <srs_app_reload.hpp>
#include <srs_kernel_rtc_rtp.hpp>
#include <srs_kernel_rtc_rtcp.hpp>
#include <srs_app_rtc_queue.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_app_rtc_dtls.hpp>
#include <srs_service_conn.hpp>
#include <srs_app_conn.hpp>
#include <srs_app_rtc_conn.hpp>
#include <srs_app_quic_conn.hpp>

#include <string>
#include <map>
#include <vector>
#include <sys/socket.h>

class SrsQuicClient;
class SrsQuicConnection;
class SrsRtcForwardReceiver;
class SrsRtcForwardSender;

class SrsRtcForward : public ISrsRtcHijacker, public ISrsQuicConnHandler
{
public:
    SrsRtcForward();
    virtual ~SrsRtcForward();
// Interface for ISrsRtcHijacker
public:
    virtual srs_error_t initialize();
    virtual srs_error_t on_create_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req);
    virtual srs_error_t on_start_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req);
    virtual void on_stop_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req);
    virtual srs_error_t on_rtp_packet(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req, SrsRtpPacket2* pkt);
    virtual srs_error_t on_before_play(SrsRtcConnection* session, SrsRequest* req);
    virtual srs_error_t on_start_play(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req);
    virtual void on_stop_play(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req);
    virtual srs_error_t on_start_consume(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req, SrsRtcConsumer* consumer);
// Interface for ISrsQuicConnHandler
public:
    virtual srs_error_t on_new_connection(SrsQuicConnection* conn);
    virtual srs_error_t on_connection_established(SrsQuicConnection* conn);
    virtual srs_error_t on_close(SrsQuicConnection* conn);

private:
    std::map<std::string, SrsRtcForwardReceiver*> forward_stream_;
    std::map<std::string, SrsRtcForwardSender*> forward_quic_connection_;
};

class SrsRtcForwardReceiver : virtual public ISrsCoroutineHandler
{
public:
    SrsRtcForwardReceiver(SrsRequest* req);
    ~SrsRtcForwardReceiver();
public:
    srs_error_t start();
public:
    virtual srs_error_t cycle();
private:
    SrsRequest* req_;
    SrsQuicClient* quic_client_;
    SrsSTCoroutine* trd_;
    srs_cond_t cond_waiting_sdp_;
};

class SrsRtcForwardSender : virtual public ISrsQuicStreamHandler, virtual public ISrsCoroutineHandler
{
public:
    SrsRtcForwardSender();
    ~SrsRtcForwardSender();
// Interface for ISrsQuicStreamHandler
public:
    virtual srs_error_t on_stream_open(SrsQuicConnection* conn, int64_t stream_id);
    virtual srs_error_t on_stream_close(SrsQuicConnection* conn, int64_t stream_id);
    virtual srs_error_t on_stream_data(SrsQuicConnection* conn, int64_t stream_id, const uint8_t* data, size_t datalen);
public:
    virtual srs_error_t cycle();
private:
    srs_error_t process_rtc_forward_req(SrsQuicConnection* conn, int64_t stream_id, const uint8_t* data, size_t size);
private:
    SrsRequest* req_;
    SrsQuicConnection* quic_conn_;
    SrsSTCoroutine* trd_;
    int64_t media_stream_id_;
};

extern SrsRtcForward* _srs_rtc_forward;

#endif
