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

#include <srs_app_rtp_queue.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <algorithm>
#include <sstream>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_rtp.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_utility.hpp>

SrsRtpNackInfo::SrsRtpNackInfo()
{
    count_ = 0;
    generate_time_ = srs_update_system_time();
    last_req_nack_time_ = 0;
    req_nack_times_ = 0;
};

SrsRtpNackList::SrsRtpNackList(SrsRtpQueue* rtp_queue)
{
    rtp_queue_ = rtp_queue;
}

SrsRtpNackList::~SrsRtpNackList()
{
}

void SrsRtpNackList::insert(uint16_t seq)
{
    SrsRtpNackInfo& nack_info = nack_queue_[seq];

    ++nack_info.count_;
}

void SrsRtpNackList::remove(uint16_t seq)
{
    nack_queue_.erase(seq);
}

bool SrsRtpNackList::find(uint16_t seq)
{
    return nack_queue_.count(seq);
}

void SrsRtpNackList::dump()
{
    for (std::map<uint16_t, SrsRtpNackInfo>::iterator iter = nack_queue_.begin(); iter != nack_queue_.end(); ++iter) {
        srs_verbose("@rtp_queue, nack size=%u, seq=%u, generate_time=%ld, last_req_nack_time_=%ld, req_nack_times_=%d", 
            nack_queue_.size(), iter->first, iter->second.generate_time_, iter->second.last_req_nack_time_, iter->second.req_nack_times_);
    }
}

void SrsRtpNackList::get_nack_seqs(vector<uint16_t>& seqs)
{
    srs_utime_t now = srs_update_system_time();
    std::map<uint16_t, SrsRtpNackInfo>::iterator iter = nack_queue_.begin();
    while (iter != nack_queue_.end()) {
        SrsRtpNackInfo& nack_info = iter->second;

        if (now - nack_info.generate_time_ > 2000 * 1000 || nack_info.req_nack_times_ > 5) {
            srs_verbose("@rtp_queue, stop send nack req, seq=%u, from generate_time %dus, nack times=%d", 
                iter->first, (now - nack_info.generate_time_), nack_info.req_nack_times_);
            rtp_queue_->notify_drop_seq(iter->first);
            nack_queue_.erase(iter++);
            continue;
        }

        if (now - nack_info.generate_time_ < 500* 1000) {
            srs_verbose("@rtp_queue, seq=%u, generate %dus age", iter->first, now - nack_info.generate_time_);
            break;
        }

        if (now - nack_info.last_req_nack_time_ >= 200 * 1000 && nack_info.req_nack_times_ <= 5) {
            ++nack_info.req_nack_times_;
            nack_info.last_req_nack_time_ = now;
            seqs.push_back(iter->first);
        }

        ++iter;
    }
}

SrsRtpQueue::SrsRtpQueue(size_t capacity)
    : nack_(this)
{
    capacity_ = capacity;
    head_sequence_ = 0;
    highest_sequence_ = 0;
    count_ = 0;
    queue_ = new SrsRtpSharedPacket*[capacity_];
    memset(queue_, 0, sizeof(SrsRtpSharedPacket*) * capacity);
}

SrsRtpQueue::~SrsRtpQueue()
{
    srs_freepa(queue_);
}

srs_error_t SrsRtpQueue::insert(SrsRtpSharedPacket* rtp_pkt)
{
    srs_error_t err = srs_success;

    uint16_t seq = rtp_pkt->rtp_header.sequence;

    if (count_ == 0) {
        head_sequence_ = seq;
        highest_sequence_ = seq;

        srs_verbose("@rtp_queue, init head_sequence/highest_sequence=%u", seq);
    } else {
        if (nack_.find(seq)) {
            srs_verbose("@rtp_queue, seq=%u rtx success, after %d nack counts", seq, nack_.nack_queue_[seq].req_nack_times_);
            nack_.remove(seq);
        } else {
            if (seq_cmp(highest_sequence_, seq)) {
                for (uint16_t s = highest_sequence_ + 1; s != seq; ++s) {
                    srs_verbose("@rtp_queue, loss seq=%u, insert into nack list. ( > highest_sequence)", s);
                    nack_.insert(s);
                }

                highest_sequence_ = seq;
            } else {
                if (seq_cmp(seq, head_sequence_)) {
                    srs_verbose("@rtp_queue, update head sequence from %u to %u, because recv < head_sequence_", head_sequence_, seq);
                    head_sequence_ = seq;
                }
                for (uint16_t s = seq + 1; s != highest_sequence_; ++s) {
                    srs_verbose("@rtp_queue, loss seq=%u, insert into nack list. ( < highest_sequence)", s);
                    nack_.insert(s);
                }
            }
        }
    }

    while (head_sequence_ + capacity_ < highest_sequence_) {
        srs_verbose("@rtp_queue, head_sequence=%u, highest_sequence=%u", head_sequence_, highest_sequence_);
        for (uint16_t s = head_sequence_ + 1; s != highest_sequence_; ++s) {
            SrsRtpSharedPacket*& pkt = queue_[s % capacity_];
            if (pkt && pkt->rtp_video_header.is_first_packet_of_frame) {
                srs_verbose("@rtp_queue, drop packet, update head sequence from %u to %u", head_sequence_, s);
                head_sequence_ = s;
                break;
            }

            srs_verbose("@rtp_queue, drop seq=%u", s);
            nack_.remove(s);
            if (pkt && pkt->rtp_header.sequence == s) {
                delete pkt;
                pkt = NULL;
            }
        }
    }

    ++count_;

    SrsRtpSharedPacket* old_pkt = queue_[seq % capacity_];
    if (old_pkt) {
        delete old_pkt;
    }

    queue_[seq % capacity_] = rtp_pkt->copy();

    if (rtp_pkt->rtp_header.marker) {
        collect_packet();
    }

    return err;
}

void SrsRtpQueue::get_and_clean_collected_frames(std::vector<std::vector<SrsRtpSharedPacket*> >& frames)
{
    frames.swap(frames_);
}

void SrsRtpQueue::notify_drop_seq(uint16_t seq)
{
    uint16_t s = seq + 1;
    for ( ; s != highest_sequence_; ++s) {
        SrsRtpSharedPacket* pkt = queue_[s % capacity_];
        if (pkt && pkt->rtp_video_header.is_first_packet_of_frame) {
            break;
        }
    }

    srs_verbose("@rtp_queue, update head sequence from %u to %u, because seq %u stop nack", head_sequence_, s, seq);
    head_sequence_ = s;
}

void SrsRtpQueue::collect_packet()
{
    nack_.dump();

    vector<SrsRtpSharedPacket*> frame;
    for (uint16_t s = head_sequence_; s != highest_sequence_; ++s) {
        SrsRtpSharedPacket* pkt = queue_[s % capacity_];
        if (nack_.find(s)) {
            srs_verbose("@rtp_queue, seq=%u found in nack list", s);
            break;
        }

        if (s == head_sequence_ && pkt->rtp_payload_size() != 0 && ! pkt->rtp_video_header.is_first_packet_of_frame) {
            srs_verbose("@rtp_queue, seq=%u, not first packet of frame", s);
            break;
        }

        frame.push_back(pkt->copy());
        if (pkt->rtp_header.marker) {
            frames_.push_back(frame);
            frame.clear();

            srs_verbose("@rtp_queue, collect frame, update haeder sequence from %u to %u", head_sequence_, s + 1);
            head_sequence_ = s + 1;
        }
    }

    for (size_t i = 0; i < frame.size(); ++i) {
        srs_freep(frame[i]);
    }
}
