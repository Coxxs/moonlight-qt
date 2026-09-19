#include "framejitterbuffer.h"

FrameJitterBuffer::FrameJitterBuffer(Pacer* pacer, PVIDEO_STATS videoStats, int delayMs, int maxVideoFps) :
    m_Pacer(pacer),
    m_VideoStats(videoStats),
    m_DelayUs(delayMs * INT64_C(1000)),
    // Enough for delayMs worth of frames at the stream rate, plus slack for
    // fps rounding and timeline corrections that push deadlines out.
    m_Capacity((maxVideoFps * delayMs + 999) / 1000 + 2),
    m_Thread(nullptr),
    m_Stopping(false),
    m_ResetCount(0)
{
    SDL_assert(delayMs > 0);

    m_Thread = SDL_CreateThread(FrameJitterBuffer::releaseThread, "JitterBuffer", this);
    if (m_Thread == nullptr) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Unable to create jitter buffer thread: %s. Buffering disabled.",
                     SDL_GetError());
    }
    else {
        SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION,
                    "Video jitter buffer: %d ms (%d frames)",
                    delayMs, m_Capacity);
    }
}

FrameJitterBuffer::~FrameJitterBuffer()
{
    m_Lock.lock();
    m_Stopping = true;
    m_Lock.unlock();
    m_QueueChanged.wakeAll();

    if (m_Thread != nullptr) {
        SDL_WaitThread(m_Thread, nullptr);
    }

    while (!m_Queue.isEmpty()) {
        AVFrame* frame = m_Queue.dequeue().frame;
        av_frame_free(&frame);
    }
}

void FrameJitterBuffer::submitFrame(AVFrame* frame)
{
    if (m_Thread == nullptr) {
        m_Pacer->submitFrame(frame);
        return;
    }

    m_Lock.lock();

    int64_t ticks;
    if (frame->pts != AV_NOPTS_VALUE) {
        auto schedule = m_Clock.schedule(static_cast<uint32_t>(frame->pts), LiGetMicroseconds(), m_DelayUs);
        if (schedule.reset) {
            // Anything still queued was scheduled against a timeline that no longer exists
            dropQueuedFramesLocked();
            m_ResetCount++;
            SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION, "Video playout timeline reset");
        }
        ticks = schedule.ticks;
    }
    else {
        // No timing info: keep the frame in order right behind the previous one
        ticks = m_Clock.lastTicks();
    }

    m_Queue.enqueue({frame, ticks});
    m_Lock.unlock();

    m_QueueChanged.wakeOne();
}

FrameJitterBuffer::Snapshot FrameJitterBuffer::snapshot()
{
    Snapshot s;
    s.delayMs = static_cast<int>(m_DelayUs / 1000);
    s.capacity = m_Capacity;

    m_Lock.lock();
    s.queued = m_Queue.count();
    s.resetCount = m_ResetCount;
    if (s.queued > 0) {
        int64_t remainingUs = m_Clock.deadlineUs(m_Queue.last().ticks) -
                static_cast<int64_t>(LiGetMicroseconds());
        s.occupancyMs = remainingUs > 0 ? static_cast<int>((remainingUs + 500) / 1000) : 0;
    }
    else {
        s.occupancyMs = 0;
    }
    m_Lock.unlock();

    return s;
}

void FrameJitterBuffer::dropQueuedFramesLocked()
{
    while (!m_Queue.isEmpty()) {
        AVFrame* frame = m_Queue.dequeue().frame;
        av_frame_free(&frame);
        m_VideoStats->pacerDroppedFrames++;
    }
}

int FrameJitterBuffer::releaseThread(void* context)
{
    FrameJitterBuffer* me = reinterpret_cast<FrameJitterBuffer*>(context);

    if (SDL_SetThreadPriority(SDL_THREAD_PRIORITY_HIGH) < 0) {
        SDL_LogWarn(SDL_LOG_CATEGORY_APPLICATION,
                    "Unable to set jitter buffer thread to high priority: %s",
                    SDL_GetError());
    }

    me->m_Lock.lock();
    while (!me->m_Stopping) {
        if (me->m_Queue.isEmpty()) {
            me->m_QueueChanged.wait(&me->m_Lock);
            continue;
        }

        // A full buffer means frames are arriving faster than the timeline
        // expects. Release early and let Pacer's own drop logic sort it out
        // rather than discarding frames here.
        if (me->m_Queue.count() < me->m_Capacity) {
            int64_t remainingUs = me->m_Clock.deadlineUs(me->m_Queue.head().ticks) -
                    static_cast<int64_t>(LiGetMicroseconds());
            if (remainingUs > 0) {
                // Re-evaluate after waking: the timeline may have shifted
                me->m_QueueChanged.wait(&me->m_Lock, static_cast<unsigned long>((remainingUs + 999) / 1000));
                continue;
            }
        }

        AVFrame* frame = me->m_Queue.dequeue().frame;
        me->m_Lock.unlock();

        // Time spent here is deliberate buffering, not pacing delay, so
        // restart the pacer's queue-time measurement from this point.
        frame->pkt_dts = LiGetMicroseconds();
        me->m_Pacer->submitFrame(frame);

        me->m_Lock.lock();
    }
    me->m_Lock.unlock();

    return 0;
}
