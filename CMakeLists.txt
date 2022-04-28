cmake_minimum_required(VERSION 3.1.0)

project(glacier-settings-accounts
        VERSION 0.1
        DESCRIPTION "The Glacier settings accounts plugin")

set(CMAKE_INSTALL_PREFIX /usr)
set(CMAKE_AUTOMOC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
include(FeatureSummary)
include(GNUInstallDirs)

set(QT_MIN_VERSION "5.8.0")
find_package(Qt5 COMPONENTS Core Qml Quick LinguistTools NetworkAuth REQUIRED)

install(FILES plugins/accounts.json
        DESTINATION /usr/share/glacier-settings/plugins)

install(DIRECTORY qml/plugins/accounts
        DESTINATION /usr/share/glacier-settings/qml/plugins)

add_subdirectory(providers)

# Translations
file(GLOB TS_FILES translations/*.ts)
qt5_add_translation(QM_FILES ${TS_FILES})
add_custom_target(translations ALL DEPENDS ${QM_FILES}) # The keyword ALL is added instead add_dependencies
#add_dependencies(glacier-settings-accounts translations)
include(GNUInstallDirs) # The CMAKE_INSTALL_DATAROOTDIR is not defined by default


install(FILES ${QM_FILES}
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/glacier-settings/translations)
