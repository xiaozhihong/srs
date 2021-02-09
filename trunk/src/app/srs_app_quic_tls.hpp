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

#ifndef SRS_APP_QUIC_TLS_HPP
#define SRS_APP_QUIC_TLS_HPP

#include <srs_core.hpp>

#include <srs_app_listener.hpp>
#include <srs_app_st.hpp>
#include <srs_app_reload.hpp>
#include <srs_app_hourglass.hpp>
#include <srs_app_hybrid.hpp>

#include <openssl/ssl.h>

#include <string>

class SrsQuicTlsContext
{
public:
    SrsQuicTlsContext();
    virtual ~SrsQuicTlsContext();
public:
    SSL_CTX* get_ssl_ctx() const { return ssl_ctx_; }
public:
    virtual srs_error_t init(const std::string& key, const std::string& cert) = 0;
protected:
    SSL_CTX* ssl_ctx_;
};

class SrsQuicTlsClientContext : public SrsQuicTlsContext
{
public:
    SrsQuicTlsClientContext();
    ~SrsQuicTlsClientContext();
public:
    virtual srs_error_t init(const std::string& key, const std::string& cert);
};

class SrsQuicTlsServerContext : public SrsQuicTlsContext
{
public:
    SrsQuicTlsServerContext();
    ~SrsQuicTlsServerContext();
public:
    virtual srs_error_t init(const std::string& key, const std::string& cert);
};

class SrsQuicTlsSession
{
public:
    SrsQuicTlsSession();
    virtual ~SrsQuicTlsSession();
public:
    SSL* get_ssl() const { return ssl_; }
    virtual srs_error_t init(const SrsQuicTlsContext* quic_tls_ctx, void* handler) = 0;
protected:
    SSL* ssl_;
};

class SrsQuicTlsServerSession : public SrsQuicTlsSession
{
public:
    SrsQuicTlsServerSession();
    ~SrsQuicTlsServerSession();

    virtual srs_error_t init(const SrsQuicTlsContext* quic_tls_ctx, void* handler);
};

class SrsQuicTlsClientSession : public SrsQuicTlsSession
{
public:
    SrsQuicTlsClientSession();
    ~SrsQuicTlsClientSession();

    virtual srs_error_t init(const SrsQuicTlsContext* quic_tls_ctx, void* handler);
};

#endif
