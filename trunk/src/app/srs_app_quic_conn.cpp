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

#include <srs_app_quic_conn.hpp>

using namespace std;

#include <ngtcp2/ngtcp2_crypto.h>

#include <srs_core_autofree.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_config.hpp>
#include <srs_app_server.hpp>
#include <srs_app_quic_server.hpp>
#include <srs_app_quic_client.hpp>
#include <srs_service_utility.hpp>
#include <srs_service_st.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_tls.hpp>
#include <srs_app_quic_util.hpp>
#include <srs_app_quic_io_loop.hpp>

SrsQuicConnection::SrsQuicConnection(SrsQuicListener* listener, const SrsContextId& cid)
    : SrsQuicTransport()
{
    disposing_ = false;
    _quic_io_loop->subscribe(this);

    cid_ = cid;
    listener_ = listener;
}

SrsQuicConnection::~SrsQuicConnection()
{
    _quic_io_loop->unsubscribe(this);
    _quic_io_loop->remove(this);
}

srs_error_t SrsQuicConnection::accept(SrsUdpMuxSocket* skt, ngtcp2_pkt_hd* hd)
{
    udp_fd_ = skt->stfd();

    local_addr_ = *listener_->local_addr();
    local_addr_len_ = listener_->local_addrlen();

    remote_addr_ = *skt->peer_addr();
    remote_addr_len_ = skt->peer_addrlen();

    scid_.datalen = kServerCidLen;
    srs_generate_rand_data(scid_.data, scid_.datalen);

    dcid_ = hd->scid;
    origin_dcid_ = hd->dcid;
    
    return init(reinterpret_cast<sockaddr*>(&local_addr_), local_addr_len_, 
                reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_, 
                &scid_, &dcid_, hd->version, hd->token.base, hd->token.len);
}

srs_error_t SrsQuicConnection::on_udp_packet(SrsUdpMuxSocket* skt, const uint8_t* data, int size)
{
    remote_addr_ = *skt->peer_addr();
    remote_addr_len_ = skt->peer_addrlen();

    ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), local_addr_len_, 
        reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

    return on_data(&path, data, size);
}

ngtcp2_settings SrsQuicConnection::build_quic_settings(uint8_t* token, size_t tokenlen)
{
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);

    // TODO: FIXME: conf this values using struct like SrsQuicParam.
    settings.log_printf = ngtcp2_log_handle;
    settings.qlog.write = qlog_handle;
    settings.initial_ts = srs_get_system_time_for_quic();
  	settings.token.base = token;
  	settings.token.len = tokenlen;
  	settings.max_udp_payload_size = NGTCP2_MAX_PKTLEN_IPV4;
  	settings.cc_algo = NGTCP2_CC_ALGO_BBR;
  	settings.initial_rtt = 10 * NGTCP2_MILLISECONDS;

    return settings;
}

ngtcp2_transport_params SrsQuicConnection::build_quic_transport_params(ngtcp2_cid* original_dcid)
{
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);

  	params.initial_max_stream_data_bidi_local = kStreamDataSize;
  	params.initial_max_stream_data_bidi_remote = kStreamDataSize;
  	params.initial_max_stream_data_uni = kStreamDataSize;;
  	params.initial_max_data = 2 * kStreamDataSize;
  	params.initial_max_streams_bidi = 4;
  	params.initial_max_streams_uni = 4;
  	params.max_idle_timeout = 15 * NGTCP2_SECONDS;
  	params.stateless_reset_token_present = 1;
  	params.active_connection_id_limit = 7;

    if (original_dcid) {
        params.original_dcid = *original_dcid;
    }

    return params;
}

int SrsQuicConnection::handshake_completed()
{
	srs_trace("quic connection handshake %s completed", get_conn_name().c_str());

    uint8_t token[kMaxTokenLen];
    size_t tokenlen = sizeof(token);
    if (quic_token_->generate_token(token, tokenlen, reinterpret_cast<const sockaddr*>(&remote_addr_)) != 0) {
        return 0;
    }

    int ret = ngtcp2_conn_submit_new_token(conn_, token, tokenlen);
    if (ret != 0) {
        srs_error("ngtcp2_conn_submit_new_token failed, ret=%d", ret);
        return -1;
    }

    return 0;
}

srs_error_t SrsQuicConnection::init(sockaddr* local_addr, const socklen_t local_addrlen,
        sockaddr* remote_addr, const socklen_t remote_addrlen,
        ngtcp2_cid* scid, ngtcp2_cid* dcid, const uint32_t version, 
        uint8_t* token, const size_t tokenlen)
{
    srs_error_t err = srs_success;

    settings_ = build_quic_settings(token, tokenlen);
    transport_params_ = build_quic_transport_params(&origin_dcid_);

    ngtcp2_path path = build_quic_path(local_addr, local_addrlen, remote_addr, remote_addrlen);

    int ret = ngtcp2_conn_server_new(&conn_, dcid, scid, &path, version, &cb_, &settings_, &transport_params_, NULL, this);

    if (ret != 0) {
        return srs_error_new(ERROR_QUIC_CONN, "new quic conn failed, err=%s", ngtcp2_strerror(ret));
    }

   	tls_context_ = new SrsQuicTlsServerContext();
    // TODO: FIXME: get tls key/cert.
    string tls_key = listener_->get_key();
    string tls_cert = listener_->get_cert();
    if ((err = tls_context_->init(tls_key, tls_cert)) != srs_success) {
        return srs_error_wrap(err, "init quic tls server ctx failed");
    }

    tls_session_ = new SrsQuicTlsServerSession();
    if ((err = tls_session_->init(tls_context_, this)) != srs_success) {
        return srs_error_wrap(err, "tls session init failed");
    }

    quic_token_ = new SrsQuicToken();
    if ((err = quic_token_->init()) != srs_success) {
        return srs_error_wrap(err, "init quic token failed");
    } 

    if ((err = init_timer()) != srs_success) {
        return srs_error_wrap(err, "init timer failed");
    }

    ngtcp2_conn_set_tls_native_handle(conn_, tls_session_->get_ssl());

    return err;
}

bool SrsQuicConnection::is_alive()
{
    return true;
}

void SrsQuicConnection::on_before_dispose(ISrsResource* c)
{
    if (disposing_) {
        return;
    }

    SrsQuicConnection* quic_conn = dynamic_cast<SrsQuicConnection*>(c);
    if (quic_conn == this) {
        disposing_ = true;
    }

    if (quic_conn && quic_conn == this) {
        _srs_context->set_id(cid_);
        srs_trace("QUIC: quic_conn detach from [%s](%s), disposing=%d", c->get_id().c_str(),
            c->desc().c_str(), disposing_);
    }
}

void SrsQuicConnection::on_disposing(ISrsResource* c)
{
    if (disposing_) {
        return;
    }
}

const SrsContextId& SrsQuicConnection::get_id()
{
    return cid_;
}

std::string SrsQuicConnection::desc()
{
    return "QuicConn";
}

void SrsQuicConnection::switch_to_context()
{
    _srs_context->set_id(cid_);
}

const SrsContextId& SrsQuicConnection::context_id()
{
    return cid_;
}
