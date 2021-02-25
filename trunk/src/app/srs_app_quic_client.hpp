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

#ifndef SRS_APP_QUIC_CLIENT_HPP
#define SRS_APP_QUIC_CLIENT_HPP

#include <srs_core.hpp>
#include <srs_app_listener.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_service_st.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_reload.hpp>
#include <srs_service_conn.hpp>
#include <srs_app_conn.hpp>
#include <srs_app_quic_transport.hpp>

#include <deque>
#include <string>
#include <map>
#include <vector>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>

class SrsQuicTlsContext;
class SrsQuicTlsSession;
class SrsQuicToken;

class SrsQuicClient : public SrsQuicTransport, virtual public ISrsCoroutineHandler
{
public:
    SrsQuicClient();
  	~SrsQuicClient();
private:
    srs_error_t create_udp_socket();
    srs_error_t create_udp_io_thread();
// Interface for SrsQuicTransport
private:
    virtual ngtcp2_settings build_quic_settings(uint8_t* token , size_t tokenlen, ngtcp2_cid* original_dcid);
    virtual srs_error_t init(sockaddr* local_addr, const socklen_t local_addrlen,
        sockaddr* remote_addr, const socklen_t remote_addrlen,
        ngtcp2_cid* scid, ngtcp2_cid* dcid, const uint32_t version,
        uint8_t* token, const size_t tokenlen);

	virtual uint8_t* get_static_secret();
    virtual size_t get_static_secret_len();

	virtual int recv_stream_data(uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen);
	virtual int handshake_completed();
    virtual int on_stream_open(int64_t stream_id);
    virtual int on_stream_close(int64_t stream_id, uint64_t app_error_code);

// SrsQuicClient API
public:
    srs_error_t connect(const std::string& ip, uint16_t port);
    virtual srs_error_t open_stream(int64_t* stream_id);
    virtual srs_error_t read_stream_data(const int64_t stream_id, uint8_t* buf, const size_t buf_size, int* nb_read);	
private:
    // Quic client udp packet io recv thread.
    virtual srs_error_t cycle();

private:
    SrsSTCoroutine* trd_;
    SrsQuicTlsContext* tls_context_;
    SrsQuicToken* quic_token_;
    srs_cond_t connection_cond_;
    std::map<int64_t, srs_cond_t> stream_id_cond_;
	std::map<int64_t, std::deque<std::string> > stream_data_recv_queue_;
};

#endif
