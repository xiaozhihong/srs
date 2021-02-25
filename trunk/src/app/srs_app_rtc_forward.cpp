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

    srs_trace("rtc forward before play");

    string key = req->get_stream_url();
    map<string, SrsRtcForwardReceiver*>::iterator iter = forward_stream_.find(key);
    if (iter != forward_stream_.end()) {
        srs_trace("stream %s already started forward", key.c_str());
        return err;
    }

    SrsRtcForwardReceiver* rtc_forward_receiver = new SrsRtcForwardReceiver(req);

    if ((err = rtc_forward_receiver->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward receiver start failed");
    }

    forward_stream_[key] = rtc_forward_receiver;

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
    srs_trace("on start consume");
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    SrsRtcStreamDescription* stream_desc = rtc_source->get_stream_desc();
    if (stream_desc == NULL) {
        return err;
    }

    uint32_t media_ssrc = 0;
	for (int i = 0; i < (int)stream_desc->video_track_descs_.size(); ++i) {
        SrsRtcTrackDescription* desc = stream_desc->video_track_descs_.at(i);
        media_ssrc = desc->ssrc_;
        break;
    }

    ISrsRtcPublishStream* publish_stream = rtc_source->publish_stream();
    if (publish_stream != NULL) {
        publish_stream->request_keyframe(media_ssrc);
    }

    return err;
}

srs_error_t SrsRtcForward::on_new_connection(SrsQuicConnection* conn)
{
    return srs_success;
}

srs_error_t SrsRtcForward::on_connection_established(SrsQuicConnection* conn)
{
    srs_error_t err = srs_success;

    srs_trace("rtc forward quic conn established");

    // TODO: FIXME: manager rtc forward sender
    SrsRtcForwardSender* rtc_forward_sender = new SrsRtcForwardSender();
    conn->set_stream_handler(rtc_forward_sender);

    return err;
}

srs_error_t SrsRtcForward::on_close(SrsQuicConnection* conn)
{
    srs_error_t err = srs_success;

    return err;
}

SrsRtcForwardReceiver::SrsRtcForwardReceiver(SrsRequest* req)
{
    req_ = new SrsRequest();
    *req_ = *req;
    trd_ = NULL;
    quic_client_ = NULL;
    cond_waiting_sdp_ = srs_cond_new();
}

SrsRtcForwardReceiver::~SrsRtcForwardReceiver()
{
    srs_freep(req_);
    srs_freep(trd_);
    srs_freep(quic_client_);
    srs_cond_destroy(cond_waiting_sdp_);
}

srs_error_t SrsRtcForwardReceiver::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_receiver", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "rtc forward thread start failed");
    }

    srs_trace("waiting recv rtc sdp");
    if (srs_cond_timedwait(cond_waiting_sdp_, 1000*1000) != 0) {
        srs_warn("wait rtc forward recv sdp timeout");
    }

    return err;
}

srs_error_t SrsRtcForwardReceiver::cycle()
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

        srs_freep(quic_client_);
        quic_client_ = new SrsQuicClient();

        // TODO: FIXME:from conf.
        //string ip = "120.76.59.106";
        string ip = "127.0.0.1";
        uint16_t port = 12000;
        if ((err = quic_client_->connect(ip, port)) != srs_success) {
            return srs_error_wrap(err, "connect rtc upstream %s:%u failed", ip.c_str(), port);
        }

        srs_trace("rtc forward quic connect to %s:%u success", ip.c_str(), port);

        // TODO: FIXME: may use the code below
        /**
         *
         *  SrsQuicStream* control_stream = open_stream(0);
         *  SrsQuicStream* medai_stream =open_stream(1);
         *
         *  control_stream->write("{stream_id:media_stream->get_id()});
         */
        int64_t quic_rtc_control_stream_id = -1;
        if ((err = quic_client_->open_stream(&quic_rtc_control_stream_id)) != srs_success) {
            return srs_error_wrap(err, "open quic control stream %ld failed", quic_rtc_control_stream_id);
        }
        srs_trace("rtc forward quic open ctrl stream %ld success", quic_rtc_control_stream_id);

        int64_t quic_rtc_media_stream_id = -1;
        if ((err = quic_client_->open_stream(&quic_rtc_media_stream_id)) != srs_success) {
            return srs_error_wrap(err, "open quic media stream %ld failed", quic_rtc_media_stream_id);
        }
        srs_trace("rtc forward quic open media stream %ld success", quic_rtc_media_stream_id);


        stringstream ss;
        ss << "{\"interface\":\"rtc_forward\", \"stream_url\":{\"vhost\":\"" << req_->vhost 
           << "\",\"app\":\"" << req_->app << "\",\"stream\":\"" << req_->stream << "\"}" 
           << ",\"media_stream_id\":" << quic_rtc_media_stream_id << "}";
        string control_msg = ss.str();
        if ((err = quic_client_->write_stream_data(quic_rtc_control_stream_id, reinterpret_cast<const uint8_t*>(control_msg.data()), 
                                                   control_msg.size())) != srs_success) {
            return srs_error_wrap(err, "write quic contorl msg failed");
        }

        srs_trace("rtc forward send ctrl msg %s, waitting response", control_msg.c_str());

        // TODO: FIXME: is quic need open stream packet?
        string fake_msg = "open media stream";
        if ((err = quic_client_->write_stream_data(quic_rtc_media_stream_id, reinterpret_cast<const uint8_t*>(fake_msg.data()), 
                                                   fake_msg.size())) != srs_success) {
            return srs_error_wrap(err, "write quic media fake  msg failed");
        }

        string rsp_json;
        uint8_t ctrl_response[1500];
        int nb_read = 0;
        while (true) {
            if ((err = quic_client_->read_stream_data(quic_rtc_control_stream_id, ctrl_response, 
                            sizeof(ctrl_response), &nb_read)) != srs_success && srs_error_code(err) != ERROR_SOCKET_TIMEOUT) {
                return srs_error_wrap(err, "recv quic control msg failed");
            }
    		rsp_json.append(reinterpret_cast<const char*>(ctrl_response), nb_read);

            if (rsp_json.size() >= 2 && rsp_json[rsp_json.size() - 2] == '\r' && rsp_json[rsp_json.size() - 1] == '\n') {
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

            // Deserialize rtc stream description into SrsRtcStreamDescription, rtc play stream need negotiate 
            // to publish stream.
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
            uint8_t* rtp_data = new uint8_t[1500];
            int nb_read = 0;
            if ((err = quic_client_->read_stream_data(quic_rtc_media_stream_id, rtp_data, 
                            1500, &nb_read)) != srs_success && srs_error_code(err) != ERROR_SOCKET_TIMEOUT) {
                srs_error("recv quic media msg failed");
                break;
            }

			SrsRtpPacket2* pkt = new SrsRtpPacket2();
    		SrsAutoFree(SrsRtpPacket2, pkt);

    		if (true) {
    		    pkt->shared_msg = new SrsSharedPtrMessage();
    		    pkt->shared_msg->wrap(reinterpret_cast<char*>(rtp_data), nb_read);

                // TODO: FIXME: is it need to decode agagin?
				if (true) {
    		        SrsBuffer b(reinterpret_cast<char*>(rtp_data), nb_read);
    		        if ((err = pkt->decode(&b)) != srs_success) {
    		            return srs_error_wrap(err, "decode rtp packet");
    		        }
                }

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
}

/** TODO: FIXME: SrsQuicStream as a class
srs_error_t SrsRtcForwardSenderThread::cycle()
{
    srs_error_t err = srs_success;

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        uint8_t buf[1500];
        int nb_read = 0;
        if ((err = quic_stream->read_stream_data(stream_id, buf, sizeof(buf), &nb_read)) != 
                srs_success && srs_error_code(err) != ERROR_SOCKET_TIMEOUT) {
            return srs_error_wrap(err, "read quic stream failed");
        }
    }

    return err;
}
*/

SrsRtcForwardSender::SrsRtcForwardSender()
{
    req_ = NULL;
    trd_ = NULL;
    quic_conn_ = NULL;
    media_stream_id_ = -1;
}

SrsRtcForwardSender::~SrsRtcForwardSender()
{
    srs_freep(req_);
    srs_freep(trd_);
}

srs_error_t SrsRtcForwardSender::on_stream_open(SrsQuicConnection* conn, int64_t stream_id)
{
    return srs_success;
}

srs_error_t SrsRtcForwardSender::on_stream_close(SrsQuicConnection* conn, int64_t stream_id)
{
    return srs_success;
}

srs_error_t SrsRtcForwardSender::process_rtc_forward_req(SrsQuicConnection* conn, int64_t stream_id, const uint8_t* data, size_t size)
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

    if ((prop = json_obj->ensure_property_integer("media_stream_id")) == NULL) {
        return srs_error_wrap(err, "not media_stream_id");
    }
    media_stream_id_ = prop->to_integer();

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

    srs_trace("interface=%s, media_stream_id=%ld, stream_url=%s",
        interface.c_str(), media_stream_id_, req_->get_stream_url().c_str());

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    // Serialize rtc stream description, send back to caller.
    string rtc_stream_description = "";
    if ((err = rtc_source->get_stream_desc()->to_json(rtc_stream_description)) != srs_success) {
        return srs_error_wrap(err, "rtc stream description to json failed");
    }
    
    // TODO: FIXME: use SrsJson* class to write json.
    string control_response = "{\"rtc_stream_description\":{" + rtc_stream_description + "},";
    trd_ = new SrsSTCoroutine("rtc_forward_sender", this);
    if ((err = trd_->start()) != srs_success) {
        control_response += "\"status\":\"failed\"}";
    } else {
        control_response += "\"status\":\"success\"}";
    }
    control_response += "\r\n";

    srs_trace("rtc forward ctrl response=%s", control_response.c_str());

    return conn->write_stream_data(stream_id, reinterpret_cast<const uint8_t*>(control_response.data()), 
                                   control_response.size());
}

// TODO: FIXME: We can impl like the code below.
/**
 * srs_error_t cycle() 
 * {
 *     conn->recv_stream_data();
 * }
 */
srs_error_t SrsRtcForwardSender::on_stream_data(SrsQuicConnection* conn, int64_t stream_id, const uint8_t* data, size_t datalen)
{
    quic_conn_ = conn;

    srs_error_t err = srs_success;

    if (media_stream_id_ == -1) {
        if ((err = process_rtc_forward_req(conn, stream_id, data, datalen)) != srs_success) {
            return srs_error_wrap(err, "process rtc forward req failed");
        }
    } else {
    }

    return err;
}

srs_error_t SrsRtcForwardSender::cycle()
{
    srs_error_t err = srs_success;

	SrsRtcStream* rtc_source = NULL;
    if ((err = _srs_rtc_sources->fetch_or_create(req_, &rtc_source)) != srs_success) {
        return srs_error_wrap(err, "create rtc_source");
    }

    if (true) {
        srs_trace("on start rtc forward");
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

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

		// TODO: FIXME:don't use magic number.
        consumer->wait(1);

        // TODO: FIXME: Handle error.
        vector<SrsRtpPacket2*> pkts;
        consumer->dump_packets(pkts);

        int msg_count = (int)pkts.size();
        if (!msg_count) {
            continue;
        }

        if (! quic_conn_) {
            continue;
        }

        uint8_t buf[1500];
        for (int i = 0; i < msg_count; ++i) {
            SrsRtpPacket2* pkt = pkts[i];
            SrsBuffer stream(reinterpret_cast<char*>(buf), sizeof(buf));
            if ((err = pkt->encode(&stream)) != srs_success) {
                return srs_error_wrap(err, "encode packet");
            }

            if ((err = quic_conn_->write_stream_data(media_stream_id_, 
                    reinterpret_cast<const uint8_t*>(stream.data()), stream.pos())) != srs_success) {
                return srs_error_wrap(err, "quic write stream failed");
            }
        }
    }

    return err;
}

SrsRtcForward* _srs_rtc_forward = new SrsRtcForward();
