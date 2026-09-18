#include "../app/streaming/video/ffmpeg-renderers/pacer/playoutclock.h"

#include <cstdio>
#include <cstdlib>

static void expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(EXIT_FAILURE);
    }
}

int main()
{
    PlayoutClock clock;
    auto first = clock.schedule(0, 0, 100);
    expect(first.reset && first.timeUs == 100000, "initial prefill");
    expect(clock.schedule(1530, 17000, 100).timeUs == 117000, "normal cadence");
    auto late = clock.schedule(2970, 103000, 100);
    expect(!late.reset && late.timeUs == 133000, "70 ms jitter uses existing budget");
    expect(clock.schedule(4500, 105000, 100).timeUs == 150000, "burst arrivals retain media cadence");
    auto overdue = clock.schedule(6000, 250000, 100);
    expect(!overdue.reset && overdue.timeUs == 166666, "short underrun does not restart prefill");
    auto resumed = clock.schedule(96000, 1500000, 100);
    expect(resumed.reset && resumed.timeUs == 1600000, "long interruption rebases clock");

    PlayoutClock wrapClock;
    wrapClock.schedule(UINT32_MAX - 899, 1000000, 100);
    auto wrapped = wrapClock.schedule(0, 1010000, 100);
    expect(!wrapped.reset && wrapped.timeUs == 1110000, "32-bit RTP wraparound");
    expect(wrapClock.deadlineUs(UINT32_MAX - 899) == 1100000,
           "queued pre-wrap frame retains its deadline after wraparound");
    auto backwards = wrapClock.schedule(UINT32_MAX - 100, 1020000, 100);
    expect(backwards.reset && backwards.timeUs == 1120000, "backward timestamp rebases");

    PlayoutClock cadenceClock;
    cadenceClock.schedule(0, 0, 100);
    for (uint32_t frameIndex = 1; frameIndex <= 600; frameIndex++) {
        int64_t elapsedUs = static_cast<int64_t>(frameIndex) * 1500 * 1000 / 90;
        auto deadline = cadenceClock.schedule(frameIndex * 1500, elapsedUs, 100);
        expect(!deadline.reset && deadline.timeUs == elapsedUs + 100000,
               "60 FPS conversion does not accumulate rounding drift");
        expect(cadenceClock.deadlineUs((frameIndex - 1) * 1500) ==
                   static_cast<int64_t>(frameIndex - 1) * 1500 * 1000 / 90 + 100000,
               "older queued frame uses the same rounding origin");
    }

    PlayoutClock startupClock;
    expect(startupClock.schedule(0, 500000, 100).timeUs == 600000,
           "startup first frame establishes initial deadline");
    auto startupNext = startupClock.schedule(9000, 510000, 100);
    expect(!startupNext.reset && startupNext.timeUs == 610000,
           "startup backlog cannot impose more than requested buffering on new frames");
    expect(startupClock.deadlineUs(0) == 510000 && startupClock.deadlineUs(9000) == 610000,
           "queued timestamps use the corrected timeline without per-frame updates");
    auto startupLate = startupClock.schedule(10530, 597000, 100);
    expect(!startupLate.reset && startupLate.timeUs == 627000 && startupClock.deadlineUs(0) == 510000,
           "70 ms jitter after startup correction does not move the timeline");
    auto startupRecovered = startupClock.schedule(12060, 598000, 100);
    expect(!startupRecovered.reset && startupRecovered.timeUs == 644000,
           "burst recovery preserves media spacing");

    PlayoutClock zeroClock;
    expect(zeroClock.schedule(0, 123000, 0).timeUs == 123000, "zero delay arithmetic");
    std::puts("Playout clock tests passed");
    return EXIT_SUCCESS;
}