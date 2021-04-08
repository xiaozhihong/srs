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

#include <srs_app_rtc_forward.hpp>

using namespace std;

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sstream>

#include <srs_core_autofree.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_rtc_rtp.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_rtc_stun_stack.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_rtmp_msg_array.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_config.hpp>
#include <srs_app_rtc_queue.hpp>
#include <srs_app_source.hpp>
#include <srs_app_server.hpp>
#include <srs_service_utility.hpp>
#include <srs_http_stack.hpp>
#include <srs_app_http_api.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_service_st.hpp>
#include <srs_app_rtc_server.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_app_rtc_conn.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_rtc_forward_quic_client.hpp>

SrsRtcForward::SrsRtcForward()
{
}

SrsRtcForward::~SrsRtcForward()
{
}

srs_error_t SrsRtcForward::initialize()
{
    srs_error_t err = srs_success;
    return err;
}

srs_error_t SrsRtcForward::on_create_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req)
{
    srs_error_t err = srs_success;
    return err;
}

srs_error_t SrsRtcForward::on_start_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req)
{
    srs_error_t err = srs_success;
    return err;
}

void SrsRtcForward::on_stop_publish(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req)
{
}

srs_error_t SrsRtcForward::on_rtp_packet(SrsRtcConnection* session, SrsRtcPublishStream* publisher, SrsRequest* req, SrsRtpPacket2* pkt)
{
    // TODO: FIXME: send to the rtc forward receiver instead of using rtc consumer?
    srs_error_t err = srs_success;
    return err;
}

srs_error_t SrsRtcForward::on_before_play(SrsRtcConnection* session, SrsRequest* req)
{
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    if (! rtc_source->can_publish()) {
        // TODO: FIXME: rtc forward maybe failed? 
        srs_trace("stream %s can not publish, play directly", req->get_stream_url().c_str());
        return err;
    }

    if (rtc_source->publish_stream() != NULL) {
        // TODO: FIXME: stream already exist, but rtc forward maybe failed? 
        srs_trace("stream %s already pulled from other server", req->get_stream_url().c_str());
        return err;
    }

    // TODO: FIXME: when to free it.
    SrsRtcForwardQuicClient* rtc_forward_quic_client = new SrsRtcForwardQuicClient(req);
    if ((err = rtc_forward_quic_client->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward quic client start failed");
    }
    rtc_source->set_publish_stream(rtc_forward_quic_client);

    return err;
}

srs_error_t SrsRtcForward::on_start_play(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req)
{
    srs_error_t err = srs_success;
    return err;
}

void SrsRtcForward::on_stop_play(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req)
{
}

srs_error_t SrsRtcForward::on_start_consume(SrsRtcConnection* session, SrsRtcPlayStream* player, SrsRequest* req, SrsRtcConsumer* consumer)
{
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    SrsRtcStreamDescription* stream_desc = rtc_source->get_stream_desc();
    if (stream_desc == NULL) {
        return err;
    }

    ISrsRtcPublishStream* publish_stream = rtc_source->publish_stream();
    if (publish_stream != NULL) {
	    for (int i = 0; i < (int)stream_desc->video_track_descs_.size(); ++i) {
            SrsRtcTrackDescription* desc = stream_desc->video_track_descs_.at(i);
            if (desc != NULL) {
                publish_stream->request_keyframe(desc->ssrc_);
            }
        }
    }

    return err;
}
