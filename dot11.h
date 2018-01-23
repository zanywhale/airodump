#ifndef DOT11_H
#define DOT11_H
#include <unistd.h>
#include <stdint.h>

typedef struct radioTapHeader{
    uint8_t revision;
    uint8_t pad;
    uint16_t length;
    uint32_t flags;
}__attribute__((packed))radioTapHeader;

typedef struct ieeeDot11Frame{
    uint16_t typeInfo;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t numbers;
}__attribute__((packed))ieeeDot11Frame;

typedef struct beaconFrame{
    uint8_t timestamp[8];
    uint16_t beaconInterval;
    uint16_t capInfo;
}__attribute__((packed))beaconFrame;

typedef struct tagMetadata{
    uint8_t type;
    uint8_t length;
}__attribute__((packed))tagMetadata;

typedef struct microsofData{
    tagMetadata tag;
    uint8_t OUI[3]; // Microsof (00 50 f2)
    uint8_t vendorSpecificOUIType;
    uint8_t type;
    uint8_t version[5];
    uint16_t DataElementType;
    uint16_t DataElementLength;
    uint8_t wifiProtectionSetupState;
}__attribute((packed))microsofData;

typedef struct rsnDataTKIP{
    tagMetadata tag;
    uint16_t version;
    uint8_t groupCipherSuiteOUI[3];
    uint8_t groupCipherSuiteType;
    uint16_t pairwiseCihperSuiteCount;
    uint8_t pairwiseCipherSuiteOUI1[3];
    uint8_t pairwiseCIpherSuiteType1;
    uint8_t pairwiseCipherSuiteOUI2[3];
    uint8_t pairwiseCIpherSuiteType2;
    uint16_t authkeyManagementSuiteCount;
    uint8_t authkeyManagementOUI[3];
    uint8_t authkeyManagementType;
    uint16_t rsnCab;
}__attribute__((packed))rsnDataTKIP;

typedef struct rsnData{
    tagMetadata tag;
    uint16_t version;
    uint8_t groupCipherSuiteOUI[3];
    uint8_t groupCipherSuiteType;
    uint16_t pairwiseCihperSuiteCount;
    uint8_t pairwiseCipherSuiteOUI[3];
    uint8_t pairwiseCIpherSuiteType;
    uint16_t authkeyManagementSuiteCount;
    uint8_t authkeyManagementOUI[3];
    uint8_t authkeyManagementType;
    uint16_t rsnCab;
}__attribute__((packed))rsnData, rsnDataAES;

#endif // DOT11_H

