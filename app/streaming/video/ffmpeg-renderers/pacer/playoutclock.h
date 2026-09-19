#pragma once

#include <cstdint>

class PlayoutClock
{
public:
    struct Deadline {
        int64_t timeUs;
        bool reset;
    };

    Deadline schedule(uint32_t timestamp, int64_t nowUs, int delayMs)
    {
        int64_t delta = static_cast<uint32_t>(timestamp - m_LastTimestamp);
        if (delta > INT32_MAX) {
            delta -= INT64_C(4294967296);
        }

        int64_t ticks = m_ElapsedTicks + delta;
        int64_t deadlineUs = m_BaseUs + ticks * 1000 / 90;
        bool reset = !m_Initialized || delta < 0 || delta > 90000 ||
                nowUs - m_LastArrivalUs > 1000000 ||
                nowUs - deadlineUs > 1000000 ||
                deadlineUs - nowUs > delayMs * 1000LL + 1000000;
        if (reset) {
            m_BaseUs = nowUs + delayMs * 1000LL;
            ticks = 0;
            deadlineUs = m_BaseUs;
        }

        m_Initialized = true;
        m_LastTimestamp = timestamp;
        m_LastArrivalUs = nowUs;
        m_ElapsedTicks = ticks;
        return {deadlineUs, reset};
    }

private:
    bool m_Initialized = false;
    uint32_t m_LastTimestamp = 0;
    int64_t m_LastArrivalUs = 0;
    int64_t m_BaseUs = 0;
    int64_t m_ElapsedTicks = 0;
};