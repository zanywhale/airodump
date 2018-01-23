TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

SOURCES += main.cpp \
    packetHandler.cpp \
    apInfo.cpp \
    dump.cpp

HEADERS += \
    packetHandler.h \
    dot11.h \
    apInfo.h \
    dump.h

LIBS += -lpcap
