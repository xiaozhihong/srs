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

#include <srs_app_quic_client.hpp>

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
#include <srs_service_utility.hpp>
#include <srs_service_st.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_quic_tls.hpp>
#include <srs_app_quic_util.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

SrsQuicClient::SrsQuicClient()
    : SrsQuicTransport()
{
    trd_ = NULL;
    connection_cond_ = NULL;
}

SrsQuicClient::~SrsQuicClient()
{
    srs_freep(trd_);
    srs_close_stfd(udp_fd_);

    if (connection_cond_) {
        srs_cond_destroy(connection_cond_);
    }
}

ngtcp2_settings SrsQuicClient::build_quic_settings(uint8_t* token , size_t tokenlen, ngtcp2_cid* original_dcid)
{
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);

    // TODO: FIXME: conf this values using SrsQuicParam struct.
    settings.log_printf = ngtcp2_log_handle;
    settings.qlog.write = qlog_handle;
	settings.initial_ts = srs_get_system_time_for_quic();
  	settings.max_udp_payload_size = NGTCP2_MAX_PKTLEN_IPV4;
  	settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
  	settings.initial_rtt = 10 * NGTCP2_MILLISECONDS;

	ngtcp2_transport_params& params = settings.transport_params;
  	params.initial_max_stream_data_bidi_local = kStreamDataSize;
  	params.initial_max_stream_data_bidi_remote = kStreamDataSize;
  	params.initial_max_stream_data_uni = kStreamDataSize;;
  	params.initial_max_data = 2 * kStreamDataSize;
  	params.initial_max_streams_bidi = 4;
  	params.initial_max_streams_uni = 4;
  	params.max_idle_timeout = 15 * NGTCP2_SECONDS;
  	params.active_connection_id_limit = 7;

    return settings;
}

srs_error_t SrsQuicClient::create_udp_socket()
{
    srs_error_t err = srs_success;

    // TODO: FIXME: too complex.
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    // TODO: FIXME: Ipv6 need support?
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_NUMERICHOST;

    addrinfo* r  = NULL;
    SrsAutoFree(addrinfo, r);
    if(getaddrinfo(NULL, "0", (const addrinfo*)&hints, &r)) {
        return srs_error_new(ERROR_SYSTEM_IP_INVALID, "getaddrinfo hints=(%d,%d,%d)",
            hints.ai_family, hints.ai_socktype, hints.ai_flags);
    }

    int fd = 0;
    if ((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1) {
        return srs_error_new(ERROR_SOCKET_CREATE, "socket domain=%d, type=%d, protocol=%d",
            r->ai_family, r->ai_socktype, r->ai_protocol);
    }

    for (addrinfo* rp = r; rp; rp = rp->ai_next) {
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
    		break;
        }
  	}

    local_addr_len_ = sizeof(local_addr_);
    if (getsockname(fd, (sockaddr*)&local_addr_, &local_addr_len_) != 0) {
        return srs_error_new(ERROR_SOCKET_CREATE, "get udp socket name failed");
    }

    udp_fd_ = srs_netfd_open_socket(fd);

    if (true) {
        int except_sndbuf = 10 * 1024 * 1024;
        if ((err = srs_fd_set_sndbuf(fd, except_sndbuf)) != srs_success) {
            srs_warn("set sndbuf failed,err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        int actual_sndbuf = 0;
        if ((err = srs_fd_get_sndbuf(fd, actual_sndbuf)) != srs_success) {
            srs_warn("set sndbuf failed,err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        srs_trace("fd=%d, except_sndbuf=%d, actual_sndbuf=%d", fd, except_sndbuf, actual_sndbuf);
    }

    if (true) {
        int except_rcvbuf = 10 * 1024 * 1024;
        if ((err = srs_fd_set_rcvbuf(fd, except_rcvbuf)) != srs_success) {
            srs_warn("set rcvbuf failed,err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        int actual_rcvbuf = 0;
        if ((err = srs_fd_get_rcvbuf(fd, actual_rcvbuf)) != srs_success) {
            srs_warn("set rcvbuf failed,err=%s", srs_error_desc(err).c_str());
            srs_freep(err);
        }

        srs_trace("fd=%d, except_rcvbuf=%d, actual_rcvbuf=%d", fd, except_rcvbuf, actual_rcvbuf);
    }

	return err;
}

srs_error_t SrsQuicClient::create_udp_io_thread()
{
    srs_error_t err = srs_success;

    trd_ = new SrsSTCoroutine("quic-client-io", this);

    if ((err = trd_->start()) != srs_success) {
        return srs_error_wrap(err, "start quic client io thread failed");
    }

    return err;
}

srs_error_t SrsQuicClient::init(sockaddr* local_addr, const socklen_t local_addrlen,
        sockaddr* remote_addr, const socklen_t remote_addrlen,
        ngtcp2_cid* scid, ngtcp2_cid* dcid, const uint32_t version,
        uint8_t* token, const size_t tokenlen)
{
    srs_error_t err = srs_success;

    tls_context_ = new SrsQuicTlsClientContext();
    // Client tls init no need private key and pem file.
    if ((err = tls_context_->init("", "")) != srs_success) {
        return srs_error_wrap(err, "init quic tls client ctx failed");
    }

    tls_session_ = new SrsQuicTlsClientSession();
    if ((err = tls_session_->init(tls_context_, this)) != srs_success) {
        return srs_error_wrap(err, "tls session init failed");
    }

    quic_token_ = new SrsQuicToken();
    if ((err = quic_token_->init()) != srs_success) {
        return srs_error_wrap(err, "init quic token failed");
    }

    ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), 
        local_addr_len_, reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

    settings_ = build_quic_settings(token, tokenlen, NULL);

    int ret = ngtcp2_conn_client_new(&conn_, dcid, scid, &path,
        version, &cb_, &settings_, NULL, this);

    if (ret != 0) {
        return srs_error_new(ERROR_QUIC_CONN, "init quic client failed, err=%s", ngtcp2_strerror(ret));
    }

    ngtcp2_conn_set_tls_native_handle(conn_, tls_session_->get_ssl());

    if ((err = init_timer()) != srs_success) {
        return srs_error_wrap(err, "timer start failed");
    }

    return err;
}

srs_error_t SrsQuicClient::connect(const std::string& ip, uint16_t port, srs_utime_t timeout)
{
    srs_error_t err = srs_success;

    if ((err = create_udp_socket()) != srs_success) {
        return srs_error_wrap(err, "create socket failed");
    }

    // TODO: FIXME: global client udp loop.
    if ((err = create_udp_io_thread()) != srs_success) {
        return srs_error_wrap(err, "create udp io thread failed");
    }

    remote_addr_len_ = sizeof(remote_addr_);
    remote_addr_.sin_family = AF_INET;
    remote_addr_.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &remote_addr_.sin_addr) != 1) {
        return srs_error_new(ERROR_QUIC_CLIENT, "invalid addr=%s", ip.c_str());
    }

    // TODO: FIXME: maginc number.
    scid_.datalen = kServerCidLen;
    srs_generate_rand_data(scid_.data, scid_.datalen);
    dcid_.datalen = kClientCidLen;
    srs_generate_rand_data(dcid_.data, dcid_.datalen);

	if ((err = init(reinterpret_cast<sockaddr*>(&local_addr_), local_addr_len_,
                    reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_,
                    &scid_, &dcid_, NGTCP2_PROTO_VER_MIN, NULL, 0)) != srs_success) {
        return srs_error_wrap(err, "connect to %s:%u failed", ip.c_str(), port);
    }

    if ((err = write_protocol_data()) != srs_success) {
        return srs_error_wrap(err, "send quic client init packet failed");
    }

    connection_cond_ = srs_cond_new();
    if (srs_cond_timedwait(connection_cond_, timeout) != 0) {
        return srs_error_new(ERROR_QUIC_CLIENT, "connect to %s:%u timeout", ip.c_str(), port);
    }

    srs_trace("quic client %s connect to %s:%u success", get_conn_name().c_str(), ip.c_str(), port);
    return err;
}

int SrsQuicClient::handshake_completed()
{
    srs_trace("quic client %s handshake completed", get_conn_name().c_str());
    srs_cond_signal(connection_cond_);
    return 0;
}

srs_error_t SrsQuicClient::cycle()
{
   	srs_error_t err = srs_success;

    uint8_t buf[1600];
    int nb_buf = sizeof(buf);

    while (true) {
        if ((err = trd_->pull()) != srs_success) {
            return srs_error_wrap(err, "quic client io thread");
        }

        int nread = srs_recvfrom(udp_fd_, buf, nb_buf, (sockaddr*)&remote_addr_, (int*)&remote_addr_len_, SRS_UTIME_NO_TIMEOUT);
        if (nread <= 0) {
            srs_warn("quic client udp recv failed, ret=%d", nread);
            continue;
        }

        ngtcp2_path path = build_quic_path(reinterpret_cast<sockaddr*>(&local_addr_), local_addr_len_,
            reinterpret_cast<sockaddr*>(&remote_addr_), remote_addr_len_);

        if ((err = on_data(&path, buf, nread)) != srs_success) {
            return srs_error_wrap(err, "quic client process packet failed");
        }
	}

    return err;
}
