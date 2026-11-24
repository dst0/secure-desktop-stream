// Transient protocol/decoder oracle. No display, input, microphone or clipboard API.
#include "backend/nvcomputer.h"
#include "backend/nvpairingmanager.h"
#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSettings>
#include <QTextStream>
#include <openssl/rand.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sys/stat.h>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/sha.h>
#include <libswscale/swscale.h>
}

namespace {
constexpr int width = 1280, height = 720;
constexpr std::array<unsigned, 5> palette {0x143660, 0x2670a8, 0x32a5c0, 0x6dc6b4, 0xd4e9db};
AVCodecContext* decoder = nullptr;
SwsContext* converter = nullptr;
std::uint64_t received = 0, decoded = 0, matching = 0, motion = 0;
std::array<unsigned char, 32> previous {};
std::atomic<bool> terminated {false};
std::atomic<int> failedStage {0}, failedCode {0};
void ignoreProtocolLog(const char*, ...) {}

void require(bool condition) {
    if (!condition) throw std::runtime_error("oracle check failed");
}

bool inspectFrame(AVFrame* frame) {
    if (frame->width != width || frame->height != height || frame->format != AV_PIX_FMT_YUV420P) return false;
    if (!frame->data[0] || !frame->data[1] || !frame->data[2] ||
        frame->linesize[0] < width || frame->linesize[1] < width / 2 || frame->linesize[2] < width / 2) {
        return false;
    }
    converter = sws_getCachedContext(converter, width, height, AV_PIX_FMT_YUV420P,
        width, height, AV_PIX_FMT_RGB24, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (!converter) return false;
    const int colorspace = frame->colorspace == AVCOL_SPC_BT709 ? SWS_CS_ITU709 : SWS_CS_ITU601;
    const int* coefficients = sws_getCoefficients(colorspace);
    sws_setColorspaceDetails(converter, coefficients, frame->color_range == AVCOL_RANGE_JPEG,
        coefficients, 1, 0, 1 << 16, 1 << 16);
    std::vector<unsigned char> rgb(width * height * 3);
    unsigned char* output[] {rgb.data(), nullptr, nullptr, nullptr};
    int strides[] {width * 3, 0, 0, 0};
    if (sws_scale(converter, frame->data, frame->linesize, 0, height, output, strides) != height) return false;
    int matches = 0;
    for (int index = 0; index < 5; ++index) {
        const unsigned char* pixel = rgb.data() + (500 * width + index * 256 + 128) * 3;
        const auto expected = palette[index];
        if (std::abs(int(pixel[0]) - int(expected >> 16)) <= 24 &&
            std::abs(int(pixel[1]) - int((expected >> 8) & 255)) <= 24 &&
            std::abs(int(pixel[2]) - int(expected & 255)) <= 24) ++matches;
    }
    AVSHA* sha = av_sha_alloc();
    if (!sha) return false;
    av_sha_init(sha, 256);
    for (int y = 280; y < 380; ++y) av_sha_update(sha, frame->data[0] + y * frame->linesize[0] + 40, 1200);
    std::array<unsigned char, 32> hash {};
    av_sha_final(sha, hash.data());
    av_free(sha);
    if (decoded && hash != previous) ++motion;
    previous = hash;
    return matches == 5;
}

int setup(int format, int w, int h, int, void*, int) {
    if (format != VIDEO_FORMAT_H264 || w != width || h != height) return -1;
    decoder = avcodec_alloc_context3(avcodec_find_decoder(AV_CODEC_ID_H264));
    if (!decoder) return -1;
    decoder->thread_count = 1;
    decoder->flags |= AV_CODEC_FLAG_LOW_DELAY;
    return avcodec_open2(decoder, nullptr, nullptr);
}

int decodePacket(AVPacket* packet) {
    if (avcodec_send_packet(decoder, packet) < 0) return DR_NEED_IDR;
    AVFrame* frame = av_frame_alloc();
    if (!frame) return DR_NEED_IDR;
    int result;
    while ((result = avcodec_receive_frame(decoder, frame)) >= 0) {
        bool valid = inspectFrame(frame);
        ++decoded;
        if (valid) ++matching;
        av_frame_unref(frame);
    }
    av_frame_free(&frame);
    return result == AVERROR(EAGAIN) || result == AVERROR_EOF ? DR_OK : DR_NEED_IDR;
}

int submit(PDECODE_UNIT unit) {
    if (!unit || unit->fullLength <= 0 || unit->fullLength > 4 * 1024 * 1024) return DR_NEED_IDR;
    AVPacket* packet = av_packet_alloc();
    if (!packet || av_new_packet(packet, unit->fullLength) < 0) { av_packet_free(&packet); return DR_NEED_IDR; }
    int offset = 0;
    for (auto entry = unit->bufferList; entry; entry = entry->next) {
        if (entry->length <= 0 || entry->length > unit->fullLength - offset) { av_packet_free(&packet); return DR_NEED_IDR; }
        std::memcpy(packet->data + offset, entry->data, entry->length);
        offset += entry->length;
    }
    int result = DR_NEED_IDR;
    if (offset == unit->fullLength) { ++received; result = decodePacket(packet); }
    av_packet_free(&packet);
    return result;
}

void cleanup() {
    avcodec_free_context(&decoder);
    sws_freeContext(converter);
    converter = nullptr;
}

void selfTest() {
    AVFrame* frame = av_frame_alloc();
    require(frame);
    frame->format = AV_PIX_FMT_YUV420P; frame->width = width; frame->height = height;
    frame->colorspace = AVCOL_SPC_BT709; frame->color_range = AVCOL_RANGE_MPEG;
    require(av_frame_get_buffer(frame, 32) == 0);
    std::vector<unsigned char> rgb(width * height * 3);
    for (int y = 0; y < height; ++y) for (int x = 0; x < width; ++x) {
        auto color = palette[x / 256];
        auto pixel = rgb.data() + (y * width + x) * 3;
        pixel[0] = color >> 16; pixel[1] = color >> 8; pixel[2] = color;
    }
    SwsContext* source = sws_getContext(width, height, AV_PIX_FMT_RGB24, width, height,
        AV_PIX_FMT_YUV420P, SWS_BILINEAR, nullptr, nullptr, nullptr);
    require(source);
    const int* coefficients = sws_getCoefficients(SWS_CS_ITU709);
    sws_setColorspaceDetails(source, coefficients, 1, coefficients, 0, 0, 1 << 16, 1 << 16);
    const unsigned char* planes[] {rgb.data(), nullptr, nullptr, nullptr};
    int strides[] {width * 3, 0, 0, 0};
    require(sws_scale(source, planes, strides, 0, height, frame->data, frame->linesize) == height);
    require(inspectFrame(frame));
    decoded = 1;
    frame->data[0][300 * frame->linesize[0] + 50] ^= 255;
    require(inspectFrame(frame) && motion == 1);
    for (int y = 0; y < height; ++y) std::memset(frame->data[0] + y * frame->linesize[0], 16, width);
    for (int c = 1; c < 3; ++c) for (int y = 0; y < height / 2; ++y) std::memset(frame->data[c] + y * frame->linesize[c], 128, width / 2);
    require(!inspectFrame(frame));
    frame->width = 640; require(!inspectFrame(frame)); frame->width = width;
    const int origLinesize = frame->linesize[0];
    frame->linesize[0] = width - 1; require(!inspectFrame(frame));
    frame->linesize[0] = origLinesize;
    require(setup(VIDEO_FORMAT_H264, width, height, 30, nullptr, 0) == 0);
    DECODE_UNIT invalid {}; require(submit(&invalid) == DR_NEED_IDR);
    sws_freeContext(source); av_frame_free(&frame); cleanup();
    received = decoded = matching = motion = 0;
}
}

int main(int argc, char** argv) {
    umask(0077);
    QCoreApplication application(argc, argv);
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext&, const QString&) {});
    av_log_set_level(AV_LOG_QUIET);
    QCoreApplication::setOrganizationName("Secure Desktop Stream");
    QCoreApplication::setOrganizationDomain("secure-desktop-stream.local");
    QCoreApplication::setApplicationName("DecodeOracle");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, "/state/profile");
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, "/state/profile");
    QJsonObject receipt;
    try {
        selfTest(); receipt["oracle_self_test"] = true;
        if (argc == 2 && QString::fromLocal8Bit(argv[1]) == "--self-test") {
            QTextStream(stdout) << QJsonDocument(receipt).toJson(QJsonDocument::Compact) << Qt::endl;
            return 0;
        }
        receipt["stage"] = "arguments"; require(argc == 2);
        const QString host = QString::fromLocal8Bit(argv[1]);
        require(host == "192.0.2.10" || host == "192.0.2.20");
        receipt["stage"] = "stdin_pin";
        const QString pin = QTextStream(stdin).readLine();
        require(QRegularExpression("^[0-9]{4}$").match(pin).hasMatch());
        receipt["stage"] = "server_info";
        NvAddress address(host, 59989);
        NvHTTP http(address, 59984, QSslCertificate(), true);
        QString info = http.getServerInfo(NvHTTP::NVLL_NONE);
        receipt["stage"] = "client_identity";
        NvComputer computer(http, info);
        computer.activeAddress = address; computer.activeHttpsPort = 59984;
        QSslCertificate cert;
        NvPairingManager pairing(&computer);
        receipt["stage"] = "pair";
        require(pairing.pair(computer.appVersion, pin, cert) == NvPairingManager::PAIRED && !cert.isNull());
        receipt["paired"] = true;
        computer.serverCert = cert;
        NvHTTP authenticated(&computer);
        receipt["stage"] = "app_list";
        const auto apps = authenticated.getAppList();
        require(apps.size() == 1 && apps.front().name == "SDS Synthetic Video");
        STREAM_CONFIGURATION config; LiInitializeStreamConfiguration(&config);
        config.width = width; config.height = height; config.fps = 30; config.bitrate = 5000;
        config.packetSize = 1392; config.streamingRemotely = STREAM_CFG_LOCAL;
        config.audioConfiguration = AUDIO_CONFIGURATION_STEREO;
        config.supportedVideoFormats = VIDEO_FORMAT_H264; config.encryptionFlags = ENCFLG_ALL;
        config.enableMicrophone = false;
        require(RAND_bytes(reinterpret_cast<unsigned char*>(config.remoteInputAesKey), sizeof(config.remoteInputAesKey)) == 1);
        require(RAND_bytes(reinterpret_cast<unsigned char*>(config.remoteInputAesIv), 4) == 1);
        QString rtsp;
        receipt["stage"] = "launch";
        authenticated.startApp("launch", false, apps.front().id, &config, false, false, 0, false, rtsp);
        require(rtsp.startsWith("rtspenc://")); receipt["encrypted_rtsp"] = true;
        const QByteArray addressBytes = host.toUtf8(), version = computer.appVersion.toUtf8();
        const QByteArray gfe = computer.gfeVersion.toUtf8(), session = rtsp.toUtf8();
        SERVER_INFORMATION server; LiInitializeServerInformation(&server);
        server.address = addressBytes.constData(); server.serverInfoAppVersion = version.constData();
        server.serverInfoGfeVersion = gfe.constData(); server.rtspSessionUrl = session.constData();
        server.serverCodecModeSupport = computer.serverCodecModeSupport;
        DECODER_RENDERER_CALLBACKS video; LiInitializeVideoCallbacks(&video);
        video.setup = setup; video.cleanup = cleanup; video.submitDecodeUnit = submit;
        AUDIO_RENDERER_CALLBACKS audio; LiInitializeAudioCallbacks(&audio);
        audio.init = [](int, POPUS_MULTISTREAM_CONFIGURATION, void*, int) { return 0; };
        audio.decodeAndPlaySample = [](char*, int) {};
        CONNECTION_LISTENER_CALLBACKS listener; LiInitializeConnectionCallbacks(&listener);
        listener.logMessage = ignoreProtocolLog;
        listener.stageFailed = [](int stage, int code) { failedStage = stage; failedCode = code; };
        listener.connectionTerminated = [](int code) { failedCode = code; terminated = true; };
        receipt["stage"] = "stream";
        int connection = LiStartConnection(&server, &config, &listener, &video, &audio, nullptr, 0, nullptr, 0);
        receipt["connection_result"] = connection;
        if (connection == 0) {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
            while (!terminated && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            LiStopConnection();
        }
        receipt["received_units"] = qint64(received); receipt["decoded_frames"] = qint64(decoded);
        receipt["palette_frames"] = qint64(matching); receipt["motion_changes"] = qint64(motion);
        receipt["failed_stage"] = failedStage.load(); receipt["last_connection_code"] = failedCode.load();
        receipt["decoded_fixture"] = connection == 0 && decoded >= 60 && matching * 10 >= decoded * 9 && motion >= 5;
        QTextStream(stdout) << QJsonDocument(receipt).toJson(QJsonDocument::Compact) << Qt::endl;
        return receipt["decoded_fixture"].toBool() ? 0 : 1;
    } catch (const QtNetworkReplyException& error) {
        receipt["error"] = "network"; receipt["network_error_code"] = int(error.getError());
        QTextStream(stdout) << QJsonDocument(receipt).toJson(QJsonDocument::Compact) << Qt::endl;
        return 1;
    } catch (const GfeHttpResponseException& error) {
        receipt["error"] = "host_status"; receipt["host_status_code"] = error.getStatusCode();
        QTextStream(stdout) << QJsonDocument(receipt).toJson(QJsonDocument::Compact) << Qt::endl;
        return 1;
    } catch (...) {
        receipt["error"] = "private oracle operation failed";
        QTextStream(stdout) << QJsonDocument(receipt).toJson(QJsonDocument::Compact) << Qt::endl;
        return 1;
    }
}
