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

#ifndef SRS_APP_RTP_QUEUE_HPP
#define SRS_APP_RTP_QUEUE_HPP

#include <srs_core.hpp>

#include <string>
#include <vector>
#include <map>

class SrsRtpSharedPacket;
class SrsRtpQueue;

struct SrsRtpNackInfo
{
    SrsRtpNackInfo();

    int count_;
    srs_utime_t generate_time_;
    srs_utime_t last_req_nack_time_;
    int req_nack_times_;
};

inline bool seq_cmp(const uint16_t& l, const uint16_t& r)
{
    return ((int16_t)(r - l)) > 0;
}

struct SeqComp
{   
    bool operator()(const uint16_t& l, const uint16_t& r) const
    {   
        return seq_cmp(l, r);
    }   
};

class SrsRtpNackList
{
    friend class SrsRtpQueue;
private:
    std::map<uint16_t, SrsRtpNackInfo, SeqComp> nack_queue_;
    SrsRtpQueue* rtp_queue_;
public:
    SrsRtpNackList(SrsRtpQueue* rtp_queue);
    virtual ~SrsRtpNackList();
public:
    void insert(uint16_t seq);
    void remove(uint16_t seq);
    bool find(uint16_t seq);
    void get_nack_seqs(std::vector<uint16_t>& seqs);
public:
    void dump();
};

class SrsRtpQueue
{
private:
    size_t capacity_;
    uint16_t highest_sequence_;
    uint16_t head_sequence_;
    uint64_t count_;
    SrsRtpSharedPacket** queue_;
public:
    SrsRtpNackList nack_;
private:
    std::vector<std::vector<SrsRtpSharedPacket*> > frames_;
public:
    SrsRtpQueue(size_t capacity = 1024);
    virtual ~SrsRtpQueue();
public:
    srs_error_t insert(SrsRtpSharedPacket* rtp_pkt);
public:
    void get_and_clean_collected_frames(std::vector<std::vector<SrsRtpSharedPacket*> >& frames);
    void notify_drop_seq(uint16_t seq);
private:
    void collect_packet();
};

#endif
