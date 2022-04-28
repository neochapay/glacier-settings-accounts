install(FILES google.provider
    DESTINATION /usr/share/accounts/providers)

#install(FILES google.png
#    DESTINATION /usr/share/themes/glacier/meegotouch/icons)

install(DIRECTORY qml/
    DESTINATION /usr/share/glacier-settings/qml/plugins/accounts/providers/google)

add_subdirectory(src)
