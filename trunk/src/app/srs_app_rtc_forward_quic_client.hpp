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

#ifndef SRS_APP_RTC_FORWARD_QUIC_CLIENT_HPP
#define SRS_APP_RTC_FORWARD_QUIC_CLIENT_HPP

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

// TODO: FIXME: rename it.
// Pull rtc stream from remote, and publish rtc stream in local.
class SrsRtcForwardQuicClient : virtual public ISrsCoroutineHandler, public ISrsRtcPublishStream
{
public:
    SrsRtcForwardQuicClient(SrsRequest* req);
    ~SrsRtcForwardQuicClient();
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

#endif
