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

#ifndef GOOGLEAUTH_H
#define GOOGLEAUTH_H

#include <QOAuth2AuthorizationCodeFlow>
#include <QObject>

class GoogleAuth : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(GoogleAuth)

public:
    GoogleAuth(QObject *parent = 0);
    Q_INVOKABLE void auth();

signals:
    void configReady();
    void openUrl(const QString &authUrl);
    void authFinish();

private slots:
    void startAuth();
    void requestOpenUrl(const QUrl &url);
    void onAccessGranded();

private:
    void loadAuthDataJSON();
    QOAuth2AuthorizationCodeFlow* m_google;

    QString m_authUri;
    QString m_clientId;
    QString m_tokenUri;
    QString m_clientSecret;
};

#endif // GOOGLEAUTH_H
