install(FILES jabber.provider
    DESTINATION /usr/share/accounts/providers)

install(FILES icon-s-common-jabber.png
    DESTINATION /usr/share/themes/glacier/meegotouch/icons)

install(DIRECTORY qml/
    DESTINATION /usr/share/glacier-settings/qml/plugins/accounts/providers/jabber)
