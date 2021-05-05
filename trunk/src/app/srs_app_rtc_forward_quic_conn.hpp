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

#ifndef SRS_APP_RTC_FORWARD_QUIC_CONN_HPP
#define SRS_APP_RTC_FORWARD_QUIC_CONN_HPP

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
class SrsQuicConnection;
class SrsRtcForwardQuicStreamThread;

// TODO: FIXME: rename it.
// Process pull rtc stream requet, and send rtc stream over quic.
class SrsRtcForwardQuicConn : public ISrsResource, virtual public ISrsCoroutineHandler
{
public:
    SrsRtcForwardQuicConn(SrsQuicServer* server, SrsQuicConnection* quic_conn);
    ~SrsRtcForwardQuicConn();

    srs_error_t start();
    virtual srs_error_t cycle();
private:
    srs_error_t do_cycle();
// Interface for ISrsResource
public:
    virtual const SrsContextId& get_id();
    virtual std::string desc();
private:
    srs_error_t accept_stream();
    void clean_zombie_stream_thread();
public:
    SrsSTCoroutine* trd_;
    SrsQuicServer* server_;
    SrsQuicConnection* quic_conn_;
    std::map<int64_t, SrsRtcForwardQuicStreamThread*> stream_trds_;
};

// TODO: FIXME: rename it.
// Process pull rtc stream requet, and send rtc stream over quic.
class SrsRtcForwardQuicStreamThread : virtual public ISrsCoroutineHandler
{
public:
    SrsRtcForwardQuicStreamThread(SrsRtcForwardQuicConn* consumer, int64_t stream_id);
    ~SrsRtcForwardQuicStreamThread();
public:
    srs_error_t start();
    srs_error_t pull();
    virtual srs_error_t cycle();
private:
    srs_error_t do_cycle();
    srs_error_t process_req(srs_utime_t timeout);
    srs_error_t process_req_json(char* data, size_t size);
    srs_error_t process_rtc_forward_req(SrsJsonObject* json_obj);
    srs_error_t process_request_keyframe_req(SrsJsonObject* json_obj);
    srs_error_t do_request_keyframe();
    srs_error_t rtc_forward();
private:
    srs_error_t read_header(uint16_t& body_len, srs_utime_t timeout);
    srs_error_t read_body(void* buf, int size, srs_utime_t timeout);
private:
    SrsRtcForwardQuicConn* consumer_;
    SrsQuicConnection* quic_conn_;
    SrsRequest* req_;
    int64_t stream_id_;
    SrsSTCoroutine* trd_;
    srs_utime_t timeout_;
};

#endif
