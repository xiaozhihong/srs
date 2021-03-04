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
#include <srs_app_quic_client.hpp>
#include <srs_app_quic_conn.hpp>

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

    if (!rtc_source->can_publish()) {
        return err;
    }

    if (rtc_source->publish_stream() != NULL) {
        return err;
    }

    SrsRtcForwardPublisher* rtc_forward_publisher = new SrsRtcForwardPublisher(req);
    if ((err = rtc_forward_publisher->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward publisher start failed");
    }
    rtc_source->set_publish_stream(rtc_forward_publisher);

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

srs_error_t SrsRtcForward::on_new_stream(SrsQuicStream* stream)
{
    srs_error_t err = srs_success;

    // TODO: FIXME: manger by streamurl.
    SrsRtcForwardConsumer* rtc_forward_consumer = new SrsRtcForwardConsumer(stream);
    if ((err = rtc_forward_consumer->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward consumer start failed");
    }

    return err;
}

SrsRtcForwardPublisher::SrsRtcForwardPublisher(SrsRequest* req)
{
    req_ = new SrsRequest();
    *req_ = *req;
    trd_ = NULL;
    cond_waiting_sdp_ = srs_cond_new();
    request_keyframe_ = false;
}

SrsRtcForwardPublisher::~SrsRtcForwardPublisher()
{
    srs_freep(req_);
    srs_freep(trd_);
    srs_cond_destroy(cond_waiting_sdp_);
}

srs_error_t SrsRtcForwardPublisher::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_receiver", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward thread start failed");
    }

    srs_trace("waiting recv rtc sdp");
    if (srs_cond_timedwait(cond_waiting_sdp_, 5 * SRS_UTIME_SECONDS) != 0) {
        srs_warn("wait rtc forward recv sdp timeout");
    }

    return err;
}

srs_error_t SrsRtcForwardPublisher::cycle()
{
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    srs_trace("rtc forward receiver create stream");

    if (!rtc_source->can_publish()) {
        return srs_error_new(ERROR_RTC_SOURCE_BUSY, "stream %s busy", req_->get_stream_url().c_str());
    }

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        SrsQuicClient* quic_client = new SrsQuicClient();
        //SrsAutoFree(SrsQuicClient, quic_client);

        // TODO: FIXME:from conf.
        //string ip = "120.76.59.106";
        string ip = "127.0.0.1";
        uint16_t port = 12000;
        if ((err = quic_client->connect(ip, port)) != srs_success) {
            return srs_error_wrap(err, "connect rtc upstream %s:%u failed", ip.c_str(), port);
        }

        srs_trace("rtc forward quic connect to %s:%u success", ip.c_str(), port);

        int64_t rtc_forward_quic_stream = -1;
        SrsQuicStream* stream = NULL;
        if ((err = quic_client->open_stream(&rtc_forward_quic_stream, &stream)) != srs_success) {
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

        if (stream->write(reinterpret_cast<const uint8_t*>(control_msg.data()), control_msg.size(), 5 * SRS_UTIME_SECONDS) < 0) {
            return srs_error_new(ERROR_RTC_FORWARD, "write quic contorl msg failed");
        }

        srs_trace("rtc forward send ctrl msg %s, waitting response", control_msg.c_str());

        string rsp_json;
        uint8_t ctrl_response[1500];
        while (true) {
            int nb = stream->read(ctrl_response, sizeof(ctrl_response), 5 * SRS_UTIME_SECONDS);
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
                if (stream->write(reinterpret_cast<const uint8_t*>(req.data()), req.size(), 5 * SRS_UTIME_SECONDS) <= 0) {
                    return srs_error_new(ERROR_RTC_FORWARD, "write request_keyframe failed");
                }
                srs_trace("write request_keyframe success");
            }

            uint8_t* rtp_data = new uint8_t[1500];
            int nb = stream->read(rtp_data, 1500, 5 * SRS_UTIME_SECONDS);
            srs_verbose("recv %d nb in quic stream", nb);
            if (nb == 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
            } else if (nb < 0) {
                if (stream->get_last_error() == SrsQuicErrorTimeout) {
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

void SrsRtcForwardPublisher::request_keyframe(uint32_t ssrc)
{
    request_keyframe_ = true;
}

SrsRtcForwardConsumer::SrsRtcForwardConsumer(SrsQuicStream* stream)
{
    req_ = NULL;
    trd_ = NULL;
    stream_ = stream;
}

SrsRtcForwardConsumer::~SrsRtcForwardConsumer()
{
    srs_freep(req_);
    srs_freep(trd_);
}

srs_error_t SrsRtcForwardConsumer::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_sender", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "start rtc forward send thread failed");
    }

    return err;
}

srs_error_t SrsRtcForwardConsumer::process_req()
{
    uint8_t forward_req[1500];
    int nb = stream_->read(forward_req, sizeof(forward_req), 5 * SRS_UTIME_SECONDS);
    if (nb == 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
    } else if (nb < 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
    }

    return process_req_json(forward_req, nb);
}

srs_error_t SrsRtcForwardConsumer::process_req_json(const uint8_t* data, size_t size)
{
    srs_error_t err = srs_success;

    SrsJsonObject* json_obj = NULL;
    SrsAutoFree(SrsJsonObject, json_obj);

    string json_str(reinterpret_cast<const char*>(data), size);
    SrsJsonAny* json = SrsJsonAny::loads(json_str);
    if (!json || !json->is_object()) {
        return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", json_str.c_str());
    }

    json_obj = json->to_object();

    // Fetch params from json_obj object.
    SrsJsonAny* prop = NULL;
    if ((prop = json_obj->ensure_property_string("interface")) == NULL) {
        return srs_error_wrap(err, "not interface");
    }
    string interface = prop->to_str(); 

    if (interface == "rtc_forward") {
        return process_rtc_forward_req(json_obj);
    } else if (interface == "request_keyframe") {
        return process_request_keyframe_req(json_obj);
    } else {
        return srs_error_new(ERROR_RTC_FORWARD, "invalid req %s", interface.c_str());
    }
}

srs_error_t SrsRtcForwardConsumer::process_rtc_forward_req(SrsJsonObject* json_obj)
{
    srs_error_t err = srs_success;

    SrsJsonAny* prop = NULL;
    if ((prop = json_obj->ensure_property_object("stream_url")) == NULL) {
        return srs_error_wrap(err, "not stream_url");
    }
    SrsJsonObject* stream_url_obj = prop->to_object(); 

    if ((prop = stream_url_obj->ensure_property_string("vhost")) == NULL) {
        return srs_error_wrap(err, "not vhost");
    }
    req_ = new SrsRequest();
    req_->vhost = prop->to_str();

    if ((prop = stream_url_obj->ensure_property_string("stream")) == NULL) {
        return srs_error_wrap(err, "not stream");
    }
    req_->stream = prop->to_str();

    if ((prop = stream_url_obj->ensure_property_string("app")) == NULL) {
        return srs_error_wrap(err, "not app");
    }
    req_->app = prop->to_str();

    srs_trace("stream_url=%s", req_->get_stream_url().c_str());

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    // Serialize rtc stream description, send back to caller.
    string rtc_stream_description = "";
    SrsJsonObject* obj = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, obj);

    SrsJsonObject* obj_rtc_stream_description = SrsJsonAny::object();
    obj->set("rtc_stream_description", obj_rtc_stream_description);

    if ((err = rtc_source->get_stream_desc()->to_json(obj_rtc_stream_description)) != srs_success) {
        return srs_error_wrap(err, "rtc stream description to json failed");
    }
    
    string control_response = obj->dumps();
    // TODO: FIXME: how to split msg into quic stream.
    control_response += "\r\n";

    srs_trace("rtc forward ctrl response=%s", control_response.c_str());

    if (stream_->write(reinterpret_cast<const uint8_t*>(control_response.data()), 
                          control_response.size(), 5 * SRS_UTIME_SECONDS) < 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "write quic control req failed");
    }

    return err;
}

srs_error_t SrsRtcForwardConsumer::process_request_keyframe_req(SrsJsonObject* json_obj)
{
    srs_trace("request key frame");

    return do_request_keyframe();
}

srs_error_t SrsRtcForwardConsumer::cycle()
{
    srs_error_t err = srs_success;

    if ((err = process_req()) != srs_success) {
        return srs_error_wrap(err, "process rtc forward req failed");
    }

    if ((err = rtc_forward()) != srs_success) {
        return srs_error_wrap(err, "rtc forward failed");
    }

    return err;
}

srs_error_t SrsRtcForwardConsumer::do_request_keyframe()
{
    srs_error_t err = srs_success;

    SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    SrsRtcStreamDescription* stream_desc = rtc_source->get_stream_desc();
    if (stream_desc == NULL) {
        return err;
    }

    uint32_t media_ssrc = 0;
    ISrsRtcPublishStream* publish_stream = rtc_source->publish_stream();
    if (publish_stream != NULL) {
	    for (int i = 0; i < (int)stream_desc->video_track_descs_.size(); ++i) {
            SrsRtcTrackDescription* desc = stream_desc->video_track_descs_.at(i);
            if (desc) {
                srs_trace("request key frame of ssrc %u", desc->ssrc_);
                publish_stream->request_keyframe(desc->ssrc_);
            }
        }
    }

    return err;
}

srs_error_t SrsRtcForwardConsumer::rtc_forward()
{
    srs_error_t err = srs_success;

    if ((err = do_request_keyframe()) != srs_success) {
        return srs_error_wrap(err, "request key frame failed");
    }

    SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    // TODO: FIXME: is possible to fetch packer using ISrsRtcHijacker->on_rtp_packet?
    SrsRtcConsumer* consumer = new SrsRtcConsumer(rtc_source);
    SrsAutoFree(SrsRtcConsumer, consumer);
    if ((err = rtc_source->create_consumer(consumer)) != srs_success) {
        return srs_error_wrap(err, "create consumer, source=%s", req_->get_stream_url().c_str());
    }

    // TODO: FIXME: Dumps the SPS/PPS from gop cache, without other frames.
    if ((err = rtc_source->consumer_dumps(consumer)) != srs_success) {
        return srs_error_wrap(err, "dumps consumer, url=%s", req_->get_stream_url().c_str());
    }

    uint8_t req_buf[1500];
    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

		// TODO: FIXME:don't use magic number.
        // consumer->wait(1);
        
        int nb = stream_->read(req_buf, sizeof(req_buf), 1 * SRS_UTIME_MILLISECONDS);
        if (nb == 0) {
            return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
        } else if (nb < 0) {
            if (stream_->get_last_error() != SrsQuicErrorTimeout) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
            }
        } else {
            if ((err = process_req_json(req_buf, nb)) != srs_success) {
                return srs_error_wrap(err, "invalid req");
            }
        }

        // TODO: FIXME: Handle error.
        vector<SrsRtpPacket2*> pkts;
        consumer->dump_packets(pkts);

        int msg_count = (int)pkts.size();
        if (!msg_count) {
            continue;
        }

        if (! stream_) {
            continue;
        }

        uint8_t buf[1500];
        for (int i = 0; i < msg_count; ++i) {
            SrsRtpPacket2* pkt = pkts[i];
            SrsBuffer stream(reinterpret_cast<char*>(buf), sizeof(buf));
            if ((err = pkt->encode(&stream)) != srs_success) {
                return srs_error_wrap(err, "encode packet");
            }

            if (stream_->write(reinterpret_cast<const uint8_t*>(stream.data()), stream.pos(), 5 * SRS_UTIME_SECONDS) < 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic write stream failed");
            }
        }
    }

    return err;
}

SrsRtcForward* _srs_rtc_forward = new SrsRtcForward();
