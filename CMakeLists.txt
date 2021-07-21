cmake_minimum_required(VERSION 3.1.0)

project(glacier-settings
        VERSION 0.1
        DESCRIPTION "The Glacier settings accounts plugin")

install(FILES plugins/accounts.json
        DESTINATION /usr/share/glacier-settings/plugins)

install(DIRECTORY qml/plugins/accounts
        DESTINATION /usr/share/glacier-settings/qml/plugins)