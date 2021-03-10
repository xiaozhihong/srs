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

#include <srs_app_rtc_forward_quic_client.hpp>

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
#include <srs_app_quic_client.hpp>
#include <srs_app_quic_conn.hpp>

SrsRtcForwardQuicClient::SrsRtcForwardQuicClient(SrsRequest* req)
{
    req_ = new SrsRequest();
    *req_ = *req;
    trd_ = NULL;
    cond_waiting_sdp_ = srs_cond_new();
    request_keyframe_ = false;
}

SrsRtcForwardQuicClient::~SrsRtcForwardQuicClient()
{
    srs_freep(req_);
    srs_freep(trd_);
    srs_cond_destroy(cond_waiting_sdp_);
}

srs_error_t SrsRtcForwardQuicClient::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_receiver", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward thread start failed");
    }

    srs_trace("waiting recv rtc sdp");
    if (srs_cond_timedwait(cond_waiting_sdp_, 5 * SRS_UTIME_SECONDS) != 0) {
        srs_freep(trd_);
        return srs_error_new(ERROR_RTC_FORWARD, "wait rtc forward recv sdp timeout");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicClient::cycle()
{
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    srs_trace("rtc forward receiver create stream");

    if (! rtc_source->can_publish()) {
        return srs_error_new(ERROR_RTC_SOURCE_BUSY, "stream %s busy", req_->get_stream_url().c_str());
    }

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        SrsQuicClient* quic_client = new SrsQuicClient();
        SrsAutoFree(SrsQuicClient, quic_client);

        // TODO: FIXME: ip:port from config file.
        string ip = "127.0.0.1";
        uint16_t port = 12000;
        if ((err = quic_client->connect(ip, port)) != srs_success) {
            return srs_error_wrap(err, "connect rtc upstream %s:%u failed", ip.c_str(), port);
        }

        srs_trace("rtc forward quic connect to %s:%u success", ip.c_str(), port);

        int64_t rtc_forward_quic_stream = -1;
        if ((err = quic_client->open_stream(&rtc_forward_quic_stream)) != srs_success) {
            return srs_error_wrap(err, "open quic control stream %ld failed", rtc_forward_quic_stream);
        }

        srs_trace("rtc forward quic open ctrl stream %ld success", rtc_forward_quic_stream);

        SrsJsonObject* obj = SrsJsonAny::object();
        SrsAutoFree(SrsJsonObject, obj);

        obj->set("interface", SrsJsonAny::str("rtc_forward"));

        SrsJsonObject* obj_stream_url = SrsJsonAny::object();
        obj->set("stream_url", obj_stream_url);

        obj_stream_url->set("vhost", SrsJsonAny::str(req_->vhost.c_str()));
        obj_stream_url->set("app", SrsJsonAny::str(req_->app.c_str()));
        obj_stream_url->set("stream", SrsJsonAny::str(req_->stream.c_str()));

        string control_msg = obj->dumps();

        if (quic_client->write(rtc_forward_quic_stream, reinterpret_cast<const uint8_t*>(control_msg.data()), 
                control_msg.size(), 5 * SRS_UTIME_SECONDS) < 0) {
            return srs_error_new(ERROR_RTC_FORWARD, "write quic contorl msg failed");
        }

        srs_trace("rtc forward send ctrl msg %s, waitting response", control_msg.c_str());

        string rsp_json;
        uint8_t ctrl_response[1500];
        while (true) {
            int nb = quic_client->read(rtc_forward_quic_stream, ctrl_response, sizeof(ctrl_response), 5 * SRS_UTIME_SECONDS);
            if (nb == 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
            } else if (nb < 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
            }

    		rsp_json.append(reinterpret_cast<const char*>(ctrl_response), nb);

            if (rsp_json.size() >= 2 && rsp_json[rsp_json.size() - 2] == '\r' && 
                    rsp_json[rsp_json.size() - 1] == '\n') {
                rsp_json.erase(rsp_json.size() - 2, 2);
                break;
            }
        }

        if (true) {
			SrsJsonObject* req = NULL;
    		SrsAutoFree(SrsJsonObject, req);

            srs_trace("ctrl response=%s", rsp_json.c_str());
    		SrsJsonAny* json = SrsJsonAny::loads(rsp_json);
    		if (!json || !json->is_object()) {
    		    return srs_error_new(ERROR_RTC_FORWARD, "invalid body %s", rsp_json.c_str());
    		}
    		req = json->to_object();

    		// Fetch params from req object.
    		SrsJsonAny* prop = NULL;
    		if ((prop = req->ensure_property_object("rtc_stream_description")) == NULL) {
    		    return srs_error_new(ERROR_RTC_FORWARD, "json no found rtc_stream_description", rsp_json.c_str());
    		}

            // Deserialize rtc stream description into SrsRtcStreamDescription, 
            // rtc play stream need negotiate to publish stream.
            SrsJsonObject* obj = prop->to_object();
            SrsRtcStreamDescription* stream_desc = new SrsRtcStreamDescription();
            if ((err = stream_desc->from_json(obj)) != srs_success) {
                return srs_error_wrap(err, "parse rtc_stream_description failed");
            }

            rtc_source->set_stream_created();
            rtc_source->set_stream_desc(stream_desc);
        }

        srs_cond_signal(cond_waiting_sdp_);

        while (true) {
            if (request_keyframe_) {
                request_keyframe_ = false;

                SrsJsonObject* obj = SrsJsonAny::object();
                SrsAutoFree(SrsJsonObject, obj);
                obj->set("interface", SrsJsonAny::str("request_keyframe"));
                string req = obj->dumps();
                if (quic_client->write(rtc_forward_quic_stream, reinterpret_cast<const uint8_t*>(req.data()), req.size(), 5 * SRS_UTIME_SECONDS) <= 0) {
                    return srs_error_new(ERROR_RTC_FORWARD, "write request_keyframe failed");
                }
                srs_trace("write request_keyframe success");
            }

            uint8_t* rtp_data = new uint8_t[1500];
            int nb = quic_client->read(rtc_forward_quic_stream, rtp_data, 1500, 5 * SRS_UTIME_SECONDS);
            srs_verbose("recv %d nb in quic stream", nb);
            if (nb == 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
            } else if (nb < 0) {
                if (quic_client->get_last_error() == SrsQuicErrorTimeout) {
                    continue;
                }
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
            }

			SrsRtpPacket2* pkt = new SrsRtpPacket2();
    		SrsAutoFree(SrsRtpPacket2, pkt);

            // TODO: FIXME: is it need to decode agagin?
			if (true) {
    		    SrsBuffer b(reinterpret_cast<char*>(rtp_data), nb);
    		    if ((err = pkt->decode(&b)) != srs_success) {
                    continue;
    		        return srs_error_wrap(err, "decode rtp packet");
    		    }
            }

    		pkt->shared_msg = new SrsSharedPtrMessage();
    		pkt->shared_msg->wrap(reinterpret_cast<char*>(rtp_data), nb);

            // TODO: FIXME
            if (pkt->header.get_ssrc() == rtc_source->get_stream_desc()->audio_track_desc_->ssrc_) {
                pkt->frame_type = SrsFrameTypeAudio;
            } else {
                pkt->frame_type = SrsFrameTypeVideo;
            }

			if ((err = rtc_source->on_rtp(pkt)) != srs_success) {
                return srs_error_wrap(err, "process rtp packet failed");
            }
        }
    }
}

void SrsRtcForwardQuicClient::request_keyframe(uint32_t ssrc)
{
    // TODO: FIXME: refine the code.
    request_keyframe_ = true;
}
