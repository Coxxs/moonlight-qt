#pragma once

#include <QThread>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QNetworkProxy>
#include <QSslConfiguration>
#include <QUrl>
#include <QUuid>
#include <QEventLoop>

#include <SDL.h>

#include "backend/nvcomputer.h"
#include "backend/identitymanager.h"

// Worker that lives on the ClipboardManager thread
class ClipboardWorker : public QObject
{
    Q_OBJECT

public:
    ClipboardWorker(NvAddress address, uint16_t httpsPort, QSslCertificate serverCert)
        : m_Address(address), m_HttpsPort(httpsPort), m_ServerCert(serverCert) {}

public slots:
    void init()
    {
        m_Nam = new QNetworkAccessManager(this);
        QNetworkProxy noProxy(QNetworkProxy::NoProxy);
        m_Nam->setProxy(noProxy);

        QObject::connect(m_Nam, &QNetworkAccessManager::sslErrors,
            [this](QNetworkReply* reply, const QList<QSslError>& errors) {
                bool ignoreErrors = true;
                for (const QSslError& error : errors) {
                    if (m_ServerCert != error.certificate()) {
                        ignoreErrors = false;
                        break;
                    }
                }
                if (ignoreErrors) {
                    reply->ignoreSslErrors(errors);
                }
            });
    }

    void syncFromHost()
    {
        if (!m_Nam) return;

        QNetworkRequest request = buildRequest("/actions/clipboard", "type=text");
        QNetworkReply* reply = m_Nam->get(request);

        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        loop.exec();

        if (reply->error() == QNetworkReply::NoError) {
            QString text = QString::fromUtf8(reply->readAll());
            if (!text.isEmpty()) {
                m_LastSyncedText = text;
                SDL_SetClipboardText(text.toUtf8().constData());
            }
        }

        reply->deleteLater();
    }

    void syncToHost()
    {
        if (!m_Nam) return;

        char* sdlText = SDL_GetClipboardText();
        if (!sdlText) return;

        QString localText = QString::fromUtf8(sdlText);
        SDL_free(sdlText);

        if (localText.isEmpty() || localText == m_LastSyncedText) {
            return;
        }

        m_LastSyncedText = localText;

        QNetworkRequest request = buildRequest("/actions/clipboard", "type=text");
        request.setHeader(QNetworkRequest::ContentTypeHeader, "text/plain");

        QNetworkReply* reply = m_Nam->post(request, localText.toUtf8());

        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        loop.exec();

        reply->deleteLater();
    }

private:
    QNetworkRequest buildRequest(const QString& path, const QString& query = QString())
    {
        QUrl url;
        url.setScheme("https");
        url.setHost(m_Address.address());
        url.setPort(m_HttpsPort);
        url.setPath(path);

        QString fullQuery = "uniqueid=0123456789ABCDEF&uuid=" +
                            QUuid::createUuid().toRfc4122().toHex();
        if (!query.isEmpty()) {
            fullQuery += "&" + query;
        }
        url.setQuery(fullQuery);

        QNetworkRequest request(url);
        request.setSslConfiguration(IdentityManager::get()->getSslConfig());

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
#endif
#if QT_VERSION >= QT_VERSION_CHECK(6, 3, 0)
        request.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 0);
#endif

        return request;
    }

    NvAddress m_Address;
    uint16_t m_HttpsPort;
    QSslCertificate m_ServerCert;
    QNetworkAccessManager* m_Nam = nullptr;
    QString m_LastSyncedText;
};

class ClipboardManager : public QObject
{
    Q_OBJECT

public:
    explicit ClipboardManager(NvComputer* computer, QObject* parent = nullptr)
        : QObject(parent)
    {
        m_Worker = new ClipboardWorker(computer->activeAddress,
                                       computer->activeHttpsPort,
                                       computer->serverCert);
        m_Worker->moveToThread(&m_Thread);

        connect(&m_Thread, &QThread::started, m_Worker, &ClipboardWorker::init);
        connect(&m_Thread, &QThread::finished, m_Worker, &QObject::deleteLater);

        m_Thread.setObjectName("Clipboard Sync");
        m_Thread.start();
    }

    ~ClipboardManager()
    {
        m_Thread.quit();
        m_Thread.wait();
    }

    // Called from main thread on SDL_WINDOWEVENT_FOCUS_LOST
    void requestSyncFromHost()
    {
        QMetaObject::invokeMethod(m_Worker, "syncFromHost", Qt::QueuedConnection);
    }

    // Called from main thread on SDL_WINDOWEVENT_FOCUS_GAINED
    void requestSyncToHost()
    {
        QMetaObject::invokeMethod(m_Worker, "syncToHost", Qt::QueuedConnection);
    }

private:
    QThread m_Thread;
    ClipboardWorker* m_Worker;
};
