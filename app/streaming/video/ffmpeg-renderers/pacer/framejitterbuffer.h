#pragma once

#include "pacer.h"
#include "playoutclock.h"

#include <QQueue>
#include <QMutex>
#include <QWaitCondition>

// Optional stage between the decoder and Pacer that holds decoded frames until
// their playout deadline. It absorbs network jitter by trading a fixed amount
// of latency for smoothness. Pacer is unaware of this stage: it just sees
// frames arriving at the stream's original cadence.
class FrameJitterBuffer
{
public:
    FrameJitterBuffer(Pacer* pacer, PVIDEO_STATS videoStats, int delayMs, int maxVideoFps);

    ~FrameJitterBuffer();

    // Takes ownership of the frame. Called on the decoder thread.
    void submitFrame(AVFrame* frame);

    // Maximum number of frames held here. The decoder's frame pool must be
    // grown by this amount so buffering doesn't starve it of surfaces.
    int capacity() const { return m_Capacity; }

    struct Snapshot {
        int delayMs;
        int queued;
        int capacity;
        int occupancyMs;
        int resetCount;
    };
    Snapshot snapshot();

private:
    struct Entry {
        AVFrame* frame;
        int64_t ticks;
    };

    static int releaseThread(void* context);

    void dropQueuedFramesLocked();

    Pacer* m_Pacer;
    PVIDEO_STATS m_VideoStats;
    int64_t m_DelayUs;
    int m_Capacity;

    PlayoutClock m_Clock;
    QQueue<Entry> m_Queue;
    QMutex m_Lock;
    QWaitCondition m_QueueChanged;
    SDL_Thread* m_Thread;
    bool m_Stopping;
    int m_ResetCount;
};
