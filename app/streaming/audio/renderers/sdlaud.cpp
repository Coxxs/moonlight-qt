#include "sdl.h"
#include "settings/streamingpreferences.h"

#include <Limelight.h>

SdlAudioRenderer::SdlAudioRenderer()
    : m_AudioDevice(0),
      m_AudioBuffer(nullptr),
      m_FrameSize(0),
      m_FrameDurationMs(0),
      m_ExtraBufferingMs(0),
      m_SilenceBuffer(nullptr),
      m_SilenceBufferSize(0)
{
    SDL_assert(!SDL_WasInit(SDL_INIT_AUDIO));

    if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "SDL_InitSubSystem(SDL_INIT_AUDIO) failed: %s",
                     SDL_GetError());
        SDL_assert(SDL_WasInit(SDL_INIT_AUDIO));
    }
}

bool SdlAudioRenderer::prepareForPlayback(const OPUS_MULTISTREAM_CONFIGURATION* opusConfig)
{
    SDL_AudioSpec want, have;

    m_ExtraBufferingMs = StreamingPreferences::get()->extraBufferingMs;

    SDL_zero(want);
    want.freq = opusConfig->sampleRate;
    want.format = AUDIO_F32SYS;
    want.channels = opusConfig->channelCount;

    // On PulseAudio systems, setting a value too small can cause underruns for other
    // applications sharing this output device. We impose a floor of 480 samples (10 ms)
    // to mitigate this issue. Otherwise, we will buffer up to 3 frames of audio which
    // is 15 ms at regular 5 ms frames and 30 ms at 10 ms frames for slow connections.
    // The buffering helps avoid audio underruns due to network jitter.
    want.samples = SDL_max(480, opusConfig->samplesPerFrame * 3);

    m_FrameDurationMs = opusConfig->samplesPerFrame / (opusConfig->sampleRate / 1000);
    m_FrameSize = opusConfig->samplesPerFrame *
                  opusConfig->channelCount *
                  getAudioBufferSampleSize();

    m_AudioDevice = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (m_AudioDevice == 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Failed to open audio device: %s",
                     SDL_GetError());
        return false;
    }

    m_AudioBuffer = SDL_malloc(m_FrameSize);
    if (m_AudioBuffer == nullptr) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Failed to allocate audio buffer");
        return false;
    }

    if (m_ExtraBufferingMs > 0) {
        // The jitter buffer is built by playing this much silence ahead of the
        // real audio, so the SDL queue steadily holds m_ExtraBufferingMs more
        // than it otherwise would. This keeps the device running continuously;
        // pausing/unpausing to prefill would insert gaps on every refill.
        m_SilenceBufferSize = m_ExtraBufferingMs * (have.freq / 1000) * have.channels * getAudioBufferSampleSize();
        m_SilenceBuffer = SDL_calloc(1, m_SilenceBufferSize);
        if (m_SilenceBuffer == nullptr) {
            SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                         "Failed to allocate audio silence buffer");
            return false;
        }

        queueSilence();
    }

    SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION,
                "Desired audio buffer: %u samples (%u bytes)",
                want.samples,
                want.samples * want.channels * getAudioBufferSampleSize());

    SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION,
                "Obtained audio buffer: %u samples (%u bytes)",
                have.samples,
                have.size);

    SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION,
                "SDL audio driver: %s",
                SDL_GetCurrentAudioDriver());

    // Start playback
    SDL_PauseAudioDevice(m_AudioDevice, 0);

    return true;
}

int SdlAudioRenderer::getQueuedAudioMs()
{
    if (m_AudioDevice == 0 || m_FrameSize == 0) {
        return 0;
    }

    return static_cast<int>(SDL_GetQueuedAudioSize(m_AudioDevice) / m_FrameSize * m_FrameDurationMs);
}

int SdlAudioRenderer::extraBufferingMs()
{
    return m_ExtraBufferingMs;
}

void SdlAudioRenderer::queueSilence()
{
    if (SDL_QueueAudio(m_AudioDevice, m_SilenceBuffer, m_SilenceBufferSize) < 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Failed to queue audio silence: %s",
                     SDL_GetError());
    }
}

SdlAudioRenderer::~SdlAudioRenderer()
{
    if (m_AudioDevice != 0) {
        // Stop playback
        SDL_PauseAudioDevice(m_AudioDevice, 1);
        SDL_CloseAudioDevice(m_AudioDevice);
    }

    if (m_AudioBuffer != nullptr) {
        SDL_free(m_AudioBuffer);
    }

    if (m_SilenceBuffer != nullptr) {
        SDL_free(m_SilenceBuffer);
    }

    SDL_QuitSubSystem(SDL_INIT_AUDIO);
    SDL_assert(!SDL_WasInit(SDL_INIT_AUDIO));
}

void* SdlAudioRenderer::getAudioBuffer(int*)
{
    return m_AudioBuffer;
}

bool SdlAudioRenderer::submitAudio(int bytesWritten)
{
    if (bytesWritten == 0) {
        // Nothing to do
        return true;
    }

    // Don't queue if there's already more than 30 ms of audio data waiting
    // in Moonlight's audio queue.
    if (LiGetPendingAudioDuration() > 30 + m_ExtraBufferingMs) {
        return true;
    }

    // If the queue ran completely dry, the jitter buffer is gone and every
    // small arrival gap from here on would be audible. Whether to rebuild it
    // depends on why it drained:
    //  - Delayed packets arrive as a burst once the network recovers. That
    //    burst refills the queue on its own (up to the backpressure limit), so
    //    inserting silence here would only skip real audio. Pending audio in
    //    Moonlight's queue is the sign a burst is in flight.
    //  - Lost packets never arrive, so nothing would refill the queue. Rebuild
    //    it once with a single block of silence rather than stuttering through
    //    many tiny gaps from here on.
    if (m_ExtraBufferingMs > 0 &&
            SDL_GetQueuedAudioSize(m_AudioDevice) == 0 &&
            LiGetPendingAudioDuration() == 0) {
        SDL_LogInfo(SDL_LOG_CATEGORY_APPLICATION,
                    "Audio underrun with no pending audio; rebuilding %d ms jitter buffer",
                    m_ExtraBufferingMs);
        queueSilence();
    }

    // Provide backpressure on the queue to ensure too many frames don't build up
    // in SDL's audio queue, but don't wait forever to avoid a deadlock if the
    // audio device fails.
    for (int i = 0; i < 100; i++) {
        // Our device may enter a permanent error status upon removal, so we need
        // to recreate the audio device to pick up the new default audio device.
        if (SDL_GetAudioDeviceStatus(m_AudioDevice) == SDL_AUDIO_STOPPED) {
            return false;
        }

        // Only queue more samples where there is 50 ms or less in SDL's queue
        if (getQueuedAudioMs() <= 50 + m_ExtraBufferingMs) {
            break;
        }

        SDL_Delay(1);
    }

    if (SDL_QueueAudio(m_AudioDevice, m_AudioBuffer, bytesWritten) < 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Failed to queue audio sample: %s",
                     SDL_GetError());
    }

    return true;
}

IAudioRenderer::AudioFormat SdlAudioRenderer::getAudioBufferFormat()
{
    return AudioFormat::Float32NE;
}
