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

#include <srs_app_rtc_forward_quic_conn.hpp>

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

const int kMinRtcForwardHeaderLen = 12;
const int kMaxRtcForwardHeaderLen = 10000;

SrsRtcForwardQuicConn::SrsRtcForwardQuicConn(SrsQuicServer* server, SrsQuicConnection* quic_conn)
{
    server_ = server;
    quic_conn_ = quic_conn;
    trd_ = NULL;
}

SrsRtcForwardQuicConn::~SrsRtcForwardQuicConn()
{
    for (map<int64_t, SrsRtcForwardQuicStreamThread*>::iterator iter = stream_trds_.begin();
            iter != stream_trds_.end(); ++iter) {
        srs_freep(iter->second);
    }

    srs_freep(quic_conn_);
    srs_freep(trd_);
}

srs_error_t SrsRtcForwardQuicConn::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_quic_conn", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "start rtc forward conn thread failed");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicConn::cycle()
{
    srs_error_t err = srs_success;

    if ((err = do_cycle()) != srs_success) {
        srs_error("do cycle failed, err=%s", srs_error_desc(err).c_str());
    }

    server_->remove(this);

    return err;
}

srs_error_t SrsRtcForwardQuicConn::do_cycle()
{
    srs_error_t err = srs_success;

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "rtc forward quic conn thread failed");
        }

        if ((err = accept_stream()) != srs_success) {
            return srs_error_wrap(err, "accept stream failed");
        }

        clean_stream_thread();
    }

    return err;
}

srs_error_t SrsRtcForwardQuicConn::accept_stream()
{
    srs_error_t err = srs_success;

    int64_t stream_id = -1;
    if (quic_conn_->accept_stream(SRS_UTIME_SECONDS, stream_id) != 0) {
        if (quic_conn_->get_last_error() != SrsQuicErrorTimeout) {
            return srs_error_new(ERROR_RTC_FORWARD, "accept stream failed");
        }
        return err;
    }

    srs_trace("accept new stream %ld", stream_id);

    SrsRtcForwardQuicStreamThread* trd = new SrsRtcForwardQuicStreamThread(this, stream_id);
    if ((err = trd->start()) != srs_success) {
        srs_freep(trd);
        return srs_error_wrap(err, "rtc forward consumer start failed");
    }

    stream_trds_.insert(make_pair(stream_id, trd));

    return err;
}

void SrsRtcForwardQuicConn::clean_stream_thread()
{
    std::map<int64_t, SrsRtcForwardQuicStreamThread*>::iterator iter = stream_trds_.begin();
    while (iter != stream_trds_.end()) {
        SrsRtcForwardQuicStreamThread* stream_trd = iter->second;
        srs_error_t err = srs_success;
        if ((err = stream_trd->pull()) != srs_success) {
            srs_freep(err);
            srs_freep(stream_trd);
            stream_trds_.erase(iter++);
        } else {
            ++iter;
        }
    }
}

const SrsContextId& SrsRtcForwardQuicConn::get_id()
{
    return quic_conn_->get_id();
}

std::string SrsRtcForwardQuicConn::desc()
{
    return "RtcForwardQuicConn";
}

SrsRtcForwardQuicStreamThread::SrsRtcForwardQuicStreamThread(SrsRtcForwardQuicConn* consumer, int64_t stream_id)
{
    req_ = NULL;
    trd_ = NULL;

    consumer_ = consumer;
    quic_conn_ = consumer->quic_conn_;
    stream_id_ = stream_id;

    timeout_ = 5 * SRS_UTIME_SECONDS;
}

SrsRtcForwardQuicStreamThread::~SrsRtcForwardQuicStreamThread()
{
    srs_freep(req_);
    srs_freep(trd_);
}

srs_error_t SrsRtcForwardQuicStreamThread::start()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("rtc_forward_quic_stream_thread", this);
    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "start rtc forward send thread failed");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::pull()
{
    srs_error_t err = srs_success;

    if (trd_ == NULL) {
        return srs_error_new(ERROR_RTC_FORWARD, "null thread");
    }
    return trd_->pull();
}

srs_error_t SrsRtcForwardQuicStreamThread::read_header(uint16_t& body_len, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    char header[2];
    int nb = quic_conn_->read_fully(stream_id_, header, sizeof(header), timeout);
    if (nb == 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
    } else if (nb < 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
    }

    body_len = header[0] << 8 | header[1];
    if (body_len < kMinRtcForwardHeaderLen || body_len > kMaxRtcForwardHeaderLen) {
        return srs_error_new(ERROR_RTC_FORWARD, "invalid body size %u", body_len);
    }

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::read_body(void* buf, int size, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    int nb = quic_conn_->read_fully(stream_id_, buf, size, timeout);
    if (nb == 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream close");
    } else if (nb < 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "quic stream error");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::process_req(srs_utime_t timeout)
{
    uint16_t body_len = 0;
    srs_error_t err = srs_success;
    if ((err = read_header(body_len, timeout)) != srs_success) {
        return srs_error_wrap(err, "read header failed");
    }

    char* forward_req = new char[body_len];
    SrsAutoFreeA(char, forward_req);
    if ((err = read_body(forward_req, body_len, timeout)) != srs_success) {
        return srs_error_wrap(err, "read body failed");
    }

    return process_req_json(forward_req, body_len);
}

srs_error_t SrsRtcForwardQuicStreamThread::process_req_json(char* data, size_t size)
{
    srs_error_t err = srs_success;

    SrsJsonObject* json_obj = NULL;
    SrsAutoFree(SrsJsonObject, json_obj);

    string json_str(data, size);
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

srs_error_t SrsRtcForwardQuicStreamThread::process_rtc_forward_req(SrsJsonObject* json_obj)
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
    
    string control_response =  obj->dumps();
    uint16_t header_len = 2;
    uint16_t body_len = control_response.size();
    char* buf = new char[header_len + body_len];
    SrsAutoFreeA(char, buf);
    SrsBuffer stream(buf, header_len + body_len);
    stream.write_2bytes(body_len);
    stream.write_string(control_response);

    if (quic_conn_->write(stream_id_, stream.data(), stream.pos(), timeout_) < 0) {
        return srs_error_new(ERROR_RTC_FORWARD, "write quic control req failed");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::process_request_keyframe_req(SrsJsonObject* json_obj)
{
    return do_request_keyframe();
}

srs_error_t SrsRtcForwardQuicStreamThread::cycle()
{
    srs_error_t err = srs_success;

    if ((err = do_cycle()) != srs_success) {
        srs_error("do cycle failed, err=%s", srs_error_desc(err).c_str());
    }

    quic_conn_->close_stream(stream_id_);
    // TODO: need to close stream?

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::do_cycle()
{
    srs_error_t err = srs_success;

    if ((err = process_req(timeout_)) != srs_success) {
        return srs_error_wrap(err, "process rtc forward req failed");
    }

    if ((err = rtc_forward()) != srs_success) {
        return srs_error_wrap(err, "rtc forward failed");
    }

    return err;
}

srs_error_t SrsRtcForwardQuicStreamThread::do_request_keyframe()
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

srs_error_t SrsRtcForwardQuicStreamThread::rtc_forward()
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

    static int kMaxReqSize = 1024 * 10;
    char* req_buf = new char[kMaxReqSize];
    SrsAutoFreeA(char, req_buf);
    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "rtc forward quic conn thread failed");
        }

		// TODO: FIXME:don't use magic number.
        // consumer->wait(1);

        if ((err = process_req(SRS_UTIME_MILLISECONDS)) != srs_success) {
            if (quic_conn_->get_last_error() != SrsQuicErrorTimeout) {
                return srs_error_wrap(err, "quic stream error");
            }
        }

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

        char buf[1500];
        for (int i = 0; i < msg_count; ++i) {
            SrsRtpPacket2* pkt = pkts[i];
            // 2bytes for rtc forward quic header.
            SrsBuffer stream(buf, sizeof(buf));
            stream.write_2bytes(0);
            if ((err = pkt->encode(&stream)) != srs_success) {
                return srs_error_wrap(err, "encode packet");
            }

            if (true) {
                uint16_t rtp_size = stream.pos() - 2;
                SrsBuffer header_writer(buf, 2);
                header_writer.write_2bytes(rtp_size);
            }

            if (quic_conn_->write(stream_id_, stream.data(), stream.pos(), timeout_) < 0) {
                return srs_error_new(ERROR_RTC_FORWARD, "quic write stream failed");
            }
        }
    }

    return err;
}
