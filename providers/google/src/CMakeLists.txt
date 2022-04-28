### Sets QT_INSTALL_QML to the directory where QML Plugins should be installed
function(FindQtInstallQml)
    find_program(QMAKE NAMES qmake-qt5 qmake)
    if(NOT QMAKE)
        message(FATAL_ERROR "qmake not found")
    endif()
    execute_process(
        COMMAND ${QMAKE} -query QT_INSTALL_QML
        OUTPUT_VARIABLE PROC_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(QT_INSTALL_QML ${PROC_RESULT} PARENT_SCOPE)
endfunction()

set(SRC
    googleauth.cpp
    plugin.cpp)

add_library(nemogoogleauth SHARED ${SRC})

target_link_libraries(nemogoogleauth
    Qt5::Core
    Qt5::Qml
    Qt5::Quick
    Qt5::NetworkAuth)

FindQtInstallQml()

install(FILES qmldir DESTINATION ${QT_INSTALL_QML}/org/nemomobile/googleauth/)
install(TARGETS nemogoogleauth DESTINATION ${QT_INSTALL_QML}/org/nemomobile/googleauth/)
