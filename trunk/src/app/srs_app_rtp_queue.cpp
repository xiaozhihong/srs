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

#include <string.h>
#include <unistd.h>
#include <sstream>

using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_rtp.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_utility.hpp>

SrsRtpNackInfo::SrsRtpNackInfo()
{
    generate_time_ = srs_update_system_time();
    pre_req_nack_time_ = 0;
    req_nack_count_ = 0;
}

SrsRtpNackList::SrsRtpNackList(SrsRtpQueue* rtp_queue)
{
    rtp_queue_ = rtp_queue;
    pre_check_time_ = 0;
    
    srs_info("nack opt: max_count=%d, max_alive_time=%us, first_nack_interval=%ld, nack_interval=%ld"
        opts_.max_count, opts_.max_alive_time, opts.first_nack_interval, opts_.nack_interval);
}

SrsRtpNackList::~SrsRtpNackList()
{
}

void SrsRtpNackList::insert(uint16_t seq)
{
    SrsRtpNackInfo& nack_info = queue_[seq];
}

void SrsRtpNackList::remove(uint16_t seq)
{
    queue_.erase(seq);
}

SrsRtpNackInfo* SrsRtpNackList::find(uint16_t seq)
{
    std::map<uint16_t, SrsRtpNackInfo>::iterator iter = queue_.find(seq);
    
    if (iter == queue_.end()) {
        return NULL;
    }

    return &(iter->second);
}

void SrsRtpNackList::get_nack_seqs(vector<uint16_t>& seqs)
{
    srs_utime_t now = srs_update_system_time();
    int interval = now - pre_check_time_;
    if (interval < opts_.nack_interval / 2) {
        return;
    }

    pre_check_time_ = now;
    std::map<uint16_t, SrsRtpNackInfo>::iterator iter = queue_.begin();
    while (iter != queue_.end()) {
        const uint16_t& seq = iter->first;
        SrsRtpNackInfo& nack_info = iter->second;

        int alive_time = now - nack_info.generate_time_;
        if (alive_time > opts_.max_alive_time || nack_info.req_nack_count_ > opts_.max_count) {
            srs_verbose("NACK, drop seq=%u alive time %d bigger than max_alive_time=%d OR nack count %d bigger than %d",
                seq, alive_time, opts_.max_alive_time, nack_info.req_nack_count_, opts_.max_count);
                
            rtp_queue_->notify_drop_seq(seq);
            queue_.erase(iter++);
            continue;
        }

        if (now - nack_info.generate_time_ < opts_.first_nack_interval) {
            break;
        }

        if (now - nack_info.pre_req_nack_time_ >= opts_.nack_interval && nack_info.req_nack_count_ <= opts_.max_count) {
            ++nack_info.req_nack_count_;
            nack_info.pre_req_nack_time_ = now;
            seqs.push_back(seq);
            srs_verbose("NACK, resend seq=%u, count=%d", seq, nack_info.req_nack_count_);
        }

        ++iter;
    }
}

SrsRtpQueue::SrsRtpQueue(size_t capacity, bool one_packet_per_frame)
    : nack_(this)
{
    capacity_ = capacity;
    head_sequence_ = 0;
    highest_sequence_ = 0;
    count_ = 0;
    queue_ = new SrsRtpSharedPacket*[capacity_];
    memset(queue_, 0, sizeof(SrsRtpSharedPacket*) * capacity);

    one_packet_per_frame_ = one_packet_per_frame;
}

SrsRtpQueue::~SrsRtpQueue()
{
    srs_freepa(queue_);
}

srs_error_t SrsRtpQueue::insert(SrsRtpSharedPacket* rtp_pkt)
{
    srs_error_t err = srs_success;

    uint16_t seq = rtp_pkt->rtp_header.sequence;

    // First packet recv, init head_sequence and highest_sequence.
    if (count_ == 0) {
        head_sequence_ = seq;
        highest_sequence_ = seq;
    } else {
        SrsRtpNackInfo* nack_info = NULL;
        if ((nack_info = nack_.find(seq)) != NULL) {
            srs_utime_t now = srs_update_system_time();
            srs_verbose("seq=%u, alive time=%d, nack count=%d, rtx success", seq, now - nack_info->generate_time_, nack_info->req_nack_count_);
            nack_.remove(seq);
        } else {
            // seq > highest_sequence_
            if (seq_cmp(highest_sequence_, seq)) {
                for (uint16_t s = highest_sequence_ + 1; s != seq; ++s) {
                    srs_verbose("highest seq=%u, cur seq=%u, loss seq=%u", highest_sequence_, seq, s);
                    nack_.insert(s);
                }

                highest_sequence_ = seq;
            } else {
                // Because we don't know the ISN(initiazlie sequence number), the first packet
                // we received maybe no the first paacet client sented.
                if (seq_cmp(seq, head_sequence_)) {
                    srs_info("head seq=%u, cur seq=%u, update head seq because recv less than it.", head_sequence_, seq);
                    head_sequence_ = seq;
                }
                for (uint16_t s = seq + 1; s != highest_sequence_; ++s) {
                    srs_verbose("highest seq=%u, cur seq=%u, loss seq=%u", highest_sequence_, seq, s);
                    nack_.insert(s);
                }
            }
        }
    }

    int delay = highest_sequence_ - head_sequence_ + 1;
    srs_verbose("seqs range=[%u-%u], delay=%d", head_sequence_, highest_sequence_, delay);

    // Check seqs out of range.
    while (head_sequence_ + capacity_ < highest_sequence_) {
        srs_trace("seqs out of range, head seq=%u, hightest seq=%u", head_sequence_, highest_sequence_);
        remove(head_sequence_);
        for (uint16_t s = head_sequence_ + 1; s != highest_sequence_; ++s) {
            SrsRtpSharedPacket*& pkt = queue_[s % capacity_];
            // Choose the new head sequence. Must be the first packet of frame.
            if (pkt && pkt->rtp_payload_header->is_first_packet_of_frame) {
                head_sequence_ = s;
                break;
            }

            // Drop the seq.
            nack_.remove(s);
            srs_verbose("seqs out of range, drop seq=%u", s);
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

    // Marker bit means the last packet of frame received.
    if (rtp_pkt->rtp_header.marker || one_packet_per_frame_) {
        collect_packet();
    }

    return err;
}

srs_error_t SrsRtpQueue::remove(uint16_t seq)
{
    srs_error_t err = srs_success;

    SrsRtpSharedPacket*& pkt = queue_[seq % capacity_];
    if (pkt && pkt->rtp_header.sequence == seq) {
        delete pkt;
        pkt = NULL;
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
        if (pkt && pkt->rtp_payload_header->is_first_packet_of_frame) {
            break;
        }
    }

    srs_verbose("drop seq=%u, highest seq=%u, update head seq %u to %u", seq, highest_sequence_, head_sequence_, s);
    head_sequence_ = s;
}

void SrsRtpQueue::collect_packet()
{
    vector<SrsRtpSharedPacket*> frame;
    for (uint16_t s = head_sequence_; s != highest_sequence_; ++s) {
        SrsRtpSharedPacket* pkt = queue_[s % capacity_];
        if (nack_.find(s) != NULL) {
            srs_verbose("head seq=%u, found in nack list");
            break;
        }

        // We must collect frame from first packet to last packet.
        if (s == head_sequence_ && pkt->rtp_payload_size() != 0 && ! pkt->rtp_payload_header->is_first_packet_of_frame) {
            break;
        }

        frame.push_back(pkt->copy());
        if (pkt->rtp_header.marker || one_packet_per_frame_) {
            frames_.push_back(frame);
            frame.clear();

            srs_verbose("head seq=%u, update to %u because collect one full farme", head_sequence_, s + 1);
            head_sequence_ = s + 1;
        }
    }

    // remove the tmp buffer
    for (size_t i = 0; i < frame.size(); ++i) {
        srs_freep(frame[i]);
    }
}
