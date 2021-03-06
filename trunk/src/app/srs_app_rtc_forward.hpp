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
#include <srs_app_quic_server.hpp>

#include <string>
#include <map>
#include <vector>
#include <sys/socket.h>

class SrsJsonObject;
class SrsQuicClient;
class SrsQuicConnection;
class SrsRtcForwardPublisher;
class SrsRtcForwardConsumer;

class SrsRtcForward : public ISrsRtcHijacker, public ISrsQuicConnectionHandler
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
// Interface for ISrsQuicConnectionHandler
    virtual srs_error_t on_new_connection(SrsQuicConnection* quic_conn);
};

// TODO: FIXME: rename it.
// Pull rtc stream from remote, and publish rtc stream in local.
class SrsRtcForwardPublisher : virtual public ISrsCoroutineHandler, public ISrsRtcPublishStream
{
public:
    SrsRtcForwardPublisher(SrsRequest* req);
    ~SrsRtcForwardPublisher();
public:
    srs_error_t start();
public:
    virtual void request_keyframe(uint32_t);
    virtual srs_error_t cycle();
private:
    SrsRequest* req_;
    SrsSTCoroutine* trd_;
    srs_cond_t cond_waiting_sdp_;
    bool request_keyframe_;
};

// TODO: FIXME: rename it.
// Process pull rtc stream requet, and send rtc stream over quic.
class SrsRtcForwardConsumer : public ISrsQuicStreamHandler
{
public:
    SrsRtcForwardConsumer(SrsQuicConnection* quic_conn);
    ~SrsRtcForwardConsumer();
public:
    srs_error_t start();
// Interface for SrsQuicStream
public:
    virtual srs_error_t on_new_stream(int64_t stream_id);
public:
    SrsQuicConnection* quic_conn_;
};

// TODO: FIXME: rename it.
// Process pull rtc stream requet, and send rtc stream over quic.
class SrsRtcForwardConsumerThread : virtual public ISrsCoroutineHandler
{
public:
    SrsRtcForwardConsumerThread(SrsRtcForwardConsumer* consumer, int64_t stream_id);
    ~SrsRtcForwardConsumerThread();
public:
    srs_error_t start();
    virtual srs_error_t cycle();
private:
    srs_error_t process_req();
    srs_error_t process_req_json(const uint8_t* data, size_t size);
    srs_error_t process_rtc_forward_req(SrsJsonObject* json_obj);
    srs_error_t process_request_keyframe_req(SrsJsonObject* json_obj);
    srs_error_t do_request_keyframe();
    srs_error_t rtc_forward();
private:
    SrsRtcForwardConsumer* consumer_;
    SrsQuicConnection* quic_conn_;
    SrsRequest* req_;
    int64_t stream_id_;
    SrsSTCoroutine* trd_;
};

extern SrsRtcForward* _srs_rtc_forward;

#endif
