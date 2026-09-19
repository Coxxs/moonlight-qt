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
    auto backwards = wrapClock.schedule(UINT32_MAX - 100, 1020000, 100);
    expect(backwards.reset && backwards.timeUs == 1120000, "backward timestamp rebases");

    PlayoutClock cadenceClock;
    cadenceClock.schedule(0, 0, 100);
    for (uint32_t frameIndex = 1; frameIndex <= 600; frameIndex++) {
        int64_t elapsedUs = static_cast<int64_t>(frameIndex) * 1500 * 1000 / 90;
        auto deadline = cadenceClock.schedule(frameIndex * 1500, elapsedUs, 100);
        expect(!deadline.reset && deadline.timeUs == elapsedUs + 100000,
               "60 FPS conversion does not accumulate rounding drift");
    }

    PlayoutClock zeroClock;
    expect(zeroClock.schedule(0, 123000, 0).timeUs == 123000, "zero delay arithmetic");
    std::puts("Playout clock tests passed");
    return EXIT_SUCCESS;
}