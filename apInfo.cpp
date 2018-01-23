#include <string.h>
#include <iostream>
#include <iomanip>
#include "apInfo.h"
#include "dot11.h"
using namespace std;

apInfo::apInfo()
{
    this->beaconCnt = 0;
    this->dataCnt = 0;
    this->channel = 0;
    this->power = 0;
    strncpy(enc, "OPN\x00", 4);
    this->cipher[0] = '\x00';
    this->auth[0] = '\x00';
    this->essid[0] = '\x00';
}
apInfo::~apInfo(){}

void apInfo::setBssid(string _bssid)
{
    this->bssid = _bssid;
}

void apInfo::setPower(int _power)
{
    this->power = _power - 255;
}

void apInfo::setChannel(int _channel)
{
    this->channel = _channel;
}

void apInfo::setEnc(char *microsofInfo)
{
//    microsofData *msd;
//    msd = (microsofData *)microsofInfo;
}

void apInfo::setCipher(char *rsnInfo)
{
    rsnData *rd;
    rd = (rsnData *)rsnInfo;
    if( rd->pairwiseCIpherSuiteType == '\x04')
    {
        strncpy(this->cipher, "CCMP\x00", 5);
    }
}

void apInfo::setAuth(char *rsnInfo)
{
    rsnData *rd;
    rd = (rsnData *)rsnInfo;

    if(rd->groupCipherSuiteType == '\x02')
    {
        rsnDataTKIP *rdTKIP;
        rdTKIP = (rsnDataTKIP *)rsnInfo;
        if( rdTKIP->authkeyManagementType == '\x01')
        {
            strncpy(this->auth, "MGT\x00", 4);
        }
        else if( rdTKIP->authkeyManagementType == '\x02')
        {
            strncpy(this->auth, "PSK\x00", 4);
        }
    }
    else if(rd->groupCipherSuiteType == '\x04')
    {
        rd = (rsnDataAES *)rsnInfo;
        if( rd->authkeyManagementType == '\x01')
        {
            strncpy(this->auth, "MGT\x00", 4);
        }
        else if( rd->authkeyManagementType == '\x02')
        {
            strncpy(this->auth, "PSK\x00", 4);
        }
    }
    strncpy(this->enc, "WPA2\x00", 5);
}

void apInfo::setEssid(char _essid[32], int _length)
{
    if(_length != 0)
    {
        strncpy(this->essid, _essid, 32);
        this->essid[_length] = '\x00';
    }
    else
    {
        strncpy(this->essid, "<length:  0>", 12);
        this->essid[12] = '\x00';
    }
}

void apInfo::incDataCnt()
{
    this->dataCnt += 1;
}

void apInfo::incBeaconCnt()
{
    this->beaconCnt += 1;
}

void apInfo::printBssid()
{
    const char *tmp_bssid = this->bssid.c_str();
    printf("%02X:%02X:%02X:%02X:%02X:%02X", tmp_bssid[0]&0xff, tmp_bssid[1]&0xff, tmp_bssid[2]&0xff, tmp_bssid[3]&0xff, tmp_bssid[4]&0xff, tmp_bssid[5]&0xff);
}

void apInfo::printPower()
{
    cout << left << setw(5) << this->power;
}

void apInfo::printBeaconCnt()
{
    cout << left << setw(5) << this->beaconCnt;
}

void apInfo::printDataCnt()
{
    cout << left << setw(8) << this->dataCnt;
}

void apInfo::printChannel()
{
    cout << left << setw(5) << this->channel;
}

void apInfo::printEnc()
{
    cout << left << setw(6) << this->enc;
}

void apInfo::printCipher()
{
    cout << left << setw(8) << this->cipher;
}

void apInfo::printAuth()
{
    cout << left << setw(6) << this->auth;
}

void apInfo::printEssid()
{
    cout << left << setw(32) << essid;
}
