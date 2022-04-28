/*
 * Copyright (C) 2022 Chupligin Sergey <neochapay@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <QStandardPaths>
#include <QFile>
#include <QJsonDocument>
#include <QDebug>
#include <QJsonObject>
#include <QOAuth2AuthorizationCodeFlow>
#include <QOAuthHttpServerReplyHandler>

#include "googleauth.h"

GoogleAuth::GoogleAuth(QObject *parent) : QObject(parent)
{

}

void GoogleAuth::auth()
{
    connect(this, &GoogleAuth::configReady, this, &GoogleAuth::startAuth);
    loadAuthDataJSON();
}

void GoogleAuth::startAuth()
{
    qDebug() << Q_FUNC_INFO;

    m_google = new QOAuth2AuthorizationCodeFlow;
    m_google->setScope("email");
    m_google->setAuthorizationUrl(m_authUri);
    m_google->setClientIdentifier(m_clientId);
    m_google->setAccessTokenUrl(m_tokenUri);
    m_google->setClientIdentifierSharedKey(m_clientSecret);

    QOAuthHttpServerReplyHandler* replyHandler = new QOAuthHttpServerReplyHandler(1234, this);
    m_google->setReplyHandler(replyHandler);

    m_google->setModifyParametersFunction([](QAbstractOAuth::Stage stage, QVariantMap* parameters) {
            // Percent-decode the "code" parameter so Google can match it
            if (stage == QAbstractOAuth::Stage::RequestingAccessToken) {
                QByteArray code = parameters->value("code").toByteArray();
                (*parameters)["code"] = QUrl::fromPercentEncoding(code);
            }
    });

    connect(m_google, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            this, &GoogleAuth::requestOpenUrl);

    connect(m_google, &QOAuth2AuthorizationCodeFlow::granted,
            this, &GoogleAuth::onAccessGranded);

    m_google->grant();
}

void GoogleAuth::requestOpenUrl(const QUrl &url)
{
    qDebug() << Q_FUNC_INFO << url.toString();
    emit openUrl(url.toString());
}

void GoogleAuth::onAccessGranded()
{
    qDebug() << Q_FUNC_INFO;
    qDebug()<< "GOT TOKEN" << m_google->token();
    emit authFinish();
}

/*
 * Google auth need some personal data
 * you can use system json that stored into /usr/share/accounts/providers/google.json
 * or use user data that stored into ~/.config/accounts/google.json
*/
void GoogleAuth::loadAuthDataJSON()
{
    bool valid = false;
    QFile jsonFile(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/accounts/google.json");
    if(!jsonFile.exists()) {
        qInfo() << "User json config not exists. Use system";
        jsonFile.setFileName("/usr/share/accounts/providers/google.json");

        if(!jsonFile.exists()) {
            qWarning() << "System json config not exists";
        } else {
            valid = true;
        }
    } else {
        valid = true;
    }

    if(!valid) {
        qCritical() << "Config not found";
        return;
    }

    jsonFile.open(QIODevice::ReadOnly | QIODevice::Text);
    QJsonDocument d = QJsonDocument::fromJson(jsonFile.readAll());
    QJsonObject sett2 = d.object();
    QJsonValue value = sett2.value(QString("web"));

    QJsonObject item = value.toObject();

    m_authUri = item["auth_uri"].toString();
    m_clientId = item["client_id"].toString();
    m_tokenUri = item["token_uri"].toString();
    m_clientSecret = item["client_secret"].toString();

    if(m_authUri.isEmpty() ||
        m_clientId.isEmpty() ||
        m_tokenUri.isEmpty() ||
        m_clientSecret.isEmpty()) {
        qCritical() << "Config is wrong";
    } else {
        emit configReady();
    }
}
