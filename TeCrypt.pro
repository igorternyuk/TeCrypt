TEMPLATE = app
QT += core
QT -= gui
CONFIG += console c++1z static

INCLUDEPATH += /usr/local/ssl/include
LIBS += /usr/local/ssl/lib/libssl.a
LIBS += /usr/local/ssl/lib/libcrypto.a

CONFIG -= app_bundle
SOURCES += main.cpp \
    tecypher.cpp

HEADERS += \
    tecypher.hpp
