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
#include <srs_app_http_hooks.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_service_st.hpp>
#include <srs_app_rtc_server.hpp>
#include <srs_app_rtc_source.hpp>
#include <srs_app_rtc_conn.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_client.hpp>
#include <srs_app_quic_conn.hpp>

const int kMinRtcForwardHeaderLen = 12;
const int kMaxRtcForwardHeaderLen = 10000;

SrsRtcForwardQuicClient::SrsRtcForwardQuicClient(SrsRequest* req)
{
    req_ = new SrsRequest();
    *req_ = *req;
    trd_ = NULL;
    cond_waiting_sdp_ = srs_cond_new();
    request_keyframe_ = false;
    timeout_ = 5 * SRS_UTIME_SECONDS;
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

    // First rtc player must wait rtc stream description to negotiate.
    if (srs_cond_timedwait(cond_waiting_sdp_, timeout_) != 0) {
        srs_freep(trd_);
        return srs_error_new(ERROR_RTC_FORWARD, "rtc forward receive sdp timeout");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicClient::cycle()
{
    srs_error_t err = srs_success;

	SrsRtcSource* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    if (! rtc_source->can_publish()) {
        return srs_error_new(ERROR_RTC_SOURCE_BUSY, "stream %s busy", req_->get_stream_url().c_str());
    }

    while (true) {
		if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "rtc forward client");
        }

        SrsQuicClient* quic_client = new SrsQuicClient();
        SrsAutoFree(SrsQuicClient, quic_client);
        int64_t rtc_forward_stream = -1;

        err = do_cycle(rtc_forward_stream, quic_client, rtc_source);
        if (rtc_forward_stream != -1) {
            srs_error_t tmp_err = quic_client->close_stream(rtc_forward_stream, srs_error_code(err));
            if (tmp_err != srs_success) {
                srs_freep(tmp_err);
            }
        }

        // TODO: FIXME: config auto quic forward behavior.
        if (err != srs_success) {
            bool rtc_forward_auto_retry = false;
            if (srs_error_code(err) == ERROR_RTC_NO_NEED_FORWARD || 
                srs_error_code(err) == ERROR_RTC_CLUSTER_REDIRECT ||
                ! rtc_forward_auto_retry) {
                srs_warn("rtc forwrd client, error=%s", srs_error_desc(err).c_str());
                break;
            }

            srs_warn("rtc forwrd client, ignore error=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        srs_usleep(1 * SRS_UTIME_SECONDS);
    }

    rtc_source->on_unpublish();

    if (err != srs_success) {
        srs_error("do_cycle failed, %s", srs_error_desc(err).c_str());
    }

    return err;
}

srs_error_t SrsRtcForwardQuicClient::do_cycle(int64_t& rtc_forward_stream, 
                                              SrsQuicClient* quic_client, 
                                              SrsRtcSource* rtc_source)
{
    srs_error_t err = srs_success;

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        if ((err = connect_and_open_stream(quic_client, rtc_forward_stream)) != srs_success) {
            return srs_error_wrap(err, "connect failed");
        }

        if ((err = send_forward_req(quic_client, rtc_forward_stream, rtc_source)) != srs_success) {
            return srs_error_wrap(err, "send forward req failed");
        }

        rtc_source->on_publish();

        if ((err = recv_rtp_packet(quic_client, rtc_forward_stream, rtc_source)) != srs_success) {
            return srs_error_wrap(err, "recv rtp packet failed");
        }
    }
}

srs_error_t SrsRtcForwardQuicClient::read_header(SrsQuicClient* quic_client, int64_t stream_id, uint16_t& body_len, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    uint8_t header[2];
    if ((err = quic_client->read_fully(stream_id, header, sizeof(header), NULL, timeout)) != srs_success) {
        return srs_error_wrap(err, "read header failed");
    }

    body_len = header[0] << 8 | header[1];
    if (body_len < kMinRtcForwardHeaderLen || body_len > kMaxRtcForwardHeaderLen) {
        return srs_error_new(ERROR_RTC_FORWARD, "invalid body size %u", body_len);
    }

    return err;
}

srs_error_t SrsRtcForwardQuicClient::read_body(SrsQuicClient* quic_client, int64_t stream_id, void* buf, int size, srs_utime_t timeout)
{
    return quic_client->read_fully(stream_id, buf, size, NULL, timeout);
}

srs_error_t SrsRtcForwardQuicClient::connect_and_open_stream(SrsQuicClient* quic_client, int64_t& rtc_forward_stream)
{
    srs_error_t err = srs_success;

    string host = "";
    int port = 0;

    vector<string> coworkers = _srs_config->get_rtc_coworkers(req_->vhost);
    for (int i = 0; i < (int)coworkers.size(); i++) {
        // TODO: FIXME: User may config the server itself as coworker, we must identify and ignore it.
        string coworker = coworkers.at(i);

        string url = "http://" + coworker + "/api/v1/rtc_clusters?vhost=" + req_->vhost + "&ip=" + req_->host + 
            "&app=" + req_->app + "&stream=" + req_->stream + "&coworker=" + coworker;

        if ((err = SrsHttpHooks::discover_co_workers(url, host, port)) == srs_success) {
            break;
        }

        srs_warn("discover coworkers failed, url=%s, err=%s", url.c_str(), srs_error_desc(err).c_str());
        srs_freep(err);
    }

    if (host.empty() || port == 0) {
        return srs_error_new(ERROR_RTC_CLUSTER_REDIRECT, "no found rtc origin");
    }

    if ((err = quic_client->connect(host, port, timeout_)) != srs_success) {
        return srs_error_wrap(err, "connect rtc upstream %s:%u failed", host.c_str(), port);
    }

    srs_trace("rtc forward quic connect to %s:%u success", host.c_str(), port);

    if ((err = quic_client->open_stream(&rtc_forward_stream)) != srs_success) {
        return srs_error_wrap(err, "open rtc_forward_stream %ld failed", rtc_forward_stream);
    }

    return err;
}

srs_error_t SrsRtcForwardQuicClient::send_forward_req(SrsQuicClient* quic_client, int64_t rtc_forward_stream, SrsRtcSource* rtc_source)
{
    srs_error_t err = srs_success;

    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    obj->set("interface", SrsJsonAny::str("rtc_forward"));

    SrsJsonObject* obj_stream_url = SrsJsonAny::object();
    obj->set("stream_url", obj_stream_url);

    obj_stream_url->set("vhost", SrsJsonAny::str(req_->vhost.c_str()));
    obj_stream_url->set("app", SrsJsonAny::str(req_->app.c_str()));
    obj_stream_url->set("stream", SrsJsonAny::str(req_->stream.c_str()));

    string control_msg = "  " + obj->dumps();
    uint16_t msg_size = control_msg.size() - 2;
    SrsBuffer stream((char*)control_msg.data(), 2);
    stream.write_2bytes(msg_size);

    if ((err = quic_client->write_fully(rtc_forward_stream, control_msg.data(),
            control_msg.size(), NULL, 5 * SRS_UTIME_SECONDS)) != srs_success) {
        return srs_error_wrap(err, "write quic contorl msg failed");
    }

    srs_trace("rtc forward send req %u bytes, waitting response", control_msg.size());

    string rsp_json;
    uint16_t body_len = 0;
	if ((err = read_header(quic_client, rtc_forward_stream, body_len, timeout_)) != srs_success) {
        return srs_error_wrap(err, "read header failed");
    }

    char* ctrl_response = new char[body_len];
    if ((err = read_body(quic_client, rtc_forward_stream, ctrl_response, body_len, timeout_)) != srs_success) {
        return srs_error_wrap(err, "read body size %d failed", body_len);
    }

    rsp_json.append(ctrl_response, body_len);

	SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);

    srs_trace("stream=%s ctrl response=%s", req_->get_stream_url().c_str(), rsp_json.c_str());
    SrsJsonAny* json = SrsJsonAny::loads(rsp_json);
    if (!json || !json->is_object()) {
        return srs_error_new(ERROR_RTC_FORWARD, "invalid body %s", rsp_json.c_str());
    }
    req = json->to_object();
    if ((err = rtc_source->from_json(req)) != srs_success) {
        return srs_error_wrap(err, "unserialize rtc stream from json failed");
    }

    rtc_source->incr_forward_level();
    srs_trace("rtc forward level=%d", rtc_source->get_forward_level());

    srs_cond_signal(cond_waiting_sdp_);

    return err;
}

srs_error_t SrsRtcForwardQuicClient::recv_rtp_packet(SrsQuicClient* quic_client, int64_t rtc_forward_stream, SrsRtcSource* rtc_source)
{
    srs_error_t err = srs_success;

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        if (request_keyframe_) {
            request_keyframe_ = false;

            SrsJsonObject* obj = SrsJsonAny::object();
            SrsAutoFree(SrsJsonObject, obj);
            obj->set("interface", SrsJsonAny::str("request_keyframe"));
            string req = "  " + obj->dumps();
            uint16_t msg_size = req.size() - 2;
            SrsBuffer stream((char*)req.data(), 2);
            stream.write_2bytes(msg_size);

            if ((err = quic_client->write_fully(rtc_forward_stream, req.data(), req.size(), NULL, 5 * SRS_UTIME_SECONDS)) != srs_success) {
                return srs_error_wrap(err, "write request_keyframe failed");
            }
            srs_trace("rtc stream %s send request_keyframe req success", req_->get_stream_url().c_str());
        }

        uint16_t body_len = 0;
	    if ((err = read_header(quic_client, rtc_forward_stream, body_len, timeout_)) != srs_success) {
            return srs_error_wrap(err, "read header failed");
        }

        char* rtp_data = new char[body_len];
        SrsAutoFreeA(char, rtp_data);
        if ((err = read_body(quic_client, rtc_forward_stream, rtp_data, body_len, timeout_)) != srs_success) {
            return srs_error_wrap(err, "read body size %d failed", body_len);
        }

        SrsRtpPacket* pkt = new SrsRtpPacket();
        SrsAutoFree(SrsRtpPacket, pkt);

    	char* p = pkt->wrap(rtp_data, body_len);

    	SrsBuffer b(p, body_len);
    	if ((err = pkt->decode(&b)) != srs_success) {
    	    srs_error("decode rtp packet");
            srs_freep(err);
            continue;
    	}

        // TODO: FIXME: any better way to identify video or audio?
        if (pkt->header.get_ssrc() == rtc_source->get_stream_desc()->audio_track_desc_->ssrc_) {
            pkt->frame_type = SrsFrameTypeAudio;
        } else {
            pkt->frame_type = SrsFrameTypeVideo;
        }

		if ((err = rtc_source->on_rtp(pkt)) != srs_success) {
            return srs_error_wrap(err, "process rtp packet failed");
        }

        if (rtc_source->can_stop_forward(30 * SRS_UTIME_SECONDS)) {
            return srs_error_new(ERROR_RTC_NO_NEED_FORWARD, "no consumer, stop forward");
        }
    }
    return err;
}

void SrsRtcForwardQuicClient::request_keyframe(uint32_t ssrc)
{
    // TODO: FIXME: refine the code.
    request_keyframe_ = true;
}
