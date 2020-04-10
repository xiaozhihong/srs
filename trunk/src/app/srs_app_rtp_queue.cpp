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
    gen_ms_ = srs_get_system_time();
    last_req_ms_ = 0;
    req_nack_times_ = 0;
};

SrsRtpNackList::SrsRtpNackList()
{
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

SrsRtpQueue::SrsRtpQueue(size_t capacity)
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

        srs_verbose("init head_sequence/highest_sequence = %u", seq);
    } else {
        if (nack_.find(seq)) {
            srs_verbose("seq=%u rtx success", seq);
            nack_.remove(seq);
        } else {
            if (seq_cmp(highest_sequence_, seq)) {
                for (uint16_t s = highest_sequence_ + 1; s != seq; ++s) {
                    srs_verbose("loss seq=%u", s);
                    nack_.insert(s);
                }

                srs_verbose("update highest_sequence from %u to %u", highest_sequence_, seq);
                highest_sequence_ = seq;
            } else {
                for (uint16_t s = seq + 1; s != highest_sequence_; ++s) {
                    srs_verbose("loss seq=%u", s);
                    nack_.insert(s);
                }
            }
        }
    }

    ++count_;

    SrsRtpSharedPacket*& old_pkt = queue_[seq % capacity_];
    if (old_pkt) {
        delete old_pkt;
    }

    old_pkt = rtp_pkt;

    if (rtp_pkt->rtp_header.marker) {
        collect_packet();
    }

    return err;
}

void SrsRtpQueue::get_and_clean_collected_frames(std::vector<std::vector<SrsRtpSharedPacket*> >& frames)
{
    frames.swap(frames_);
}

void SrsRtpQueue::collect_packet()
{
    vector<SrsRtpSharedPacket*> frame;
    srs_verbose("head_sequence_=%u", head_sequence_);
    for (uint16_t s = head_sequence_; s != highest_sequence_; ++s) {
        SrsRtpSharedPacket* pkt = queue_[s % capacity_];
        if (nack_.find(s)) {
            srs_verbose("seq=%u found in nack list", s);
            break;
        }

        if (s == head_sequence_ && ! pkt->rtp_payload_size() != 0 && ! pkt->rtp_video_header.is_first_packet_of_frame) {
            srs_verbose("seq=%u, not first packet of frame", s);
            break;
        }

        frame.push_back(pkt->copy());
        if (pkt->rtp_header.marker) {
            frames_.push_back(frame);
            frame.clear();

            srs_verbose("update haeder sequence from %u to %u", head_sequence_, s + 1);
            head_sequence_ = s + 1;
        }
    }
}
