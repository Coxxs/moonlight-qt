#pragma once

#include <cstdint>

// Maps 90 kHz RTP timestamps onto the local microsecond clock.
//
// The clock defines a timeline where each frame is due `delayUs` after the
// point at which the earliest-arriving frame (relative to the media cadence)
// would have been displayed without any buffering. Frames that arrive late
// relative to that timeline eat into the delay budget instead of stalling
// playback, and bursts of frames are released at their original spacing.
//
// Adaptation is asymmetric on purpose:
//  - When a frame arrives earlier than the timeline predicts, the timeline is
//    pulled in immediately so no frame is ever held longer than `delayUs`.
//  - When frames are consistently late (the network baseline moved), the
//    timeline is pushed out once per ADAPT_WINDOW_US so that the requested
//    buffer depth is restored. This costs a one-time stall of the correction.
//
// This class is deliberately free of Qt/SDL dependencies so it can be unit
// tested in isolation.
class PlayoutClock
{
public:
    struct Schedule {
        // Position of the frame on the timeline, in 90 kHz ticks from the base.
        // Convert with deadlineUs() at wait time so timeline corrections apply
        // to frames that are already queued.
        int64_t ticks;

        // The timeline was rebuilt. Frames scheduled before this one belong to
        // a stale timeline and should be discarded.
        bool reset;
    };

    Schedule schedule(uint32_t rtpTimestamp, int64_t nowUs, int64_t delayUs)
    {
        int64_t delta = m_Initialized ? timestampDelta(rtpTimestamp, m_LastTimestamp) : 0;
        int64_t ticks = m_LastTicks + delta;

        bool reset = !m_Initialized ||
                delta < 0 ||                                // stream restarted
                delta > RESET_GAP_TICKS ||                  // media time jumped
                nowUs - m_LastArrivalUs > RESET_GAP_US ||   // long stall in arrivals
                nowUs - deadlineUs(ticks) > RESET_GAP_US;   // hopelessly behind

        if (reset) {
            m_BaseUs = nowUs + delayUs;
            ticks = 0;
            m_WindowStartUs = nowUs;
            m_WindowMaxMarginUs = delayUs;
        }
        else {
            int64_t marginUs = deadlineUs(ticks) - nowUs;
            if (marginUs > delayUs) {
                m_BaseUs -= marginUs - delayUs;
                marginUs = delayUs;
            }

            if (marginUs > m_WindowMaxMarginUs) {
                m_WindowMaxMarginUs = marginUs;
            }
            if (nowUs - m_WindowStartUs >= ADAPT_WINDOW_US) {
                if (m_WindowMaxMarginUs < delayUs) {
                    m_BaseUs += delayUs - m_WindowMaxMarginUs;
                }
                m_WindowStartUs = nowUs;
                m_WindowMaxMarginUs = INT64_MIN;
            }
        }

        m_Initialized = true;
        m_LastTimestamp = rtpTimestamp;
        m_LastArrivalUs = nowUs;
        m_LastTicks = ticks;
        return {ticks, reset};
    }

    int64_t deadlineUs(int64_t ticks) const
    {
        return m_BaseUs + ticks * 1000 / 90;
    }

    int64_t lastTicks() const
    {
        return m_LastTicks;
    }

private:
    static constexpr int64_t RESET_GAP_US = 1000000;
    static constexpr int64_t RESET_GAP_TICKS = 90000;
    static constexpr int64_t ADAPT_WINDOW_US = 1000000;

    static int64_t timestampDelta(uint32_t timestamp, uint32_t reference)
    {
        int64_t delta = static_cast<uint32_t>(timestamp - reference);
        return delta > INT32_MAX ? delta - INT64_C(4294967296) : delta;
    }

    bool m_Initialized = false;
    uint32_t m_LastTimestamp = 0;
    int64_t m_LastArrivalUs = 0;
    int64_t m_LastTicks = 0;
    int64_t m_BaseUs = 0;
    int64_t m_WindowStartUs = 0;
    int64_t m_WindowMaxMarginUs = 0;
};
