#ifndef APINFO_H
#define APINFO_H
#include <stdint.h>
#include <unordered_map>
using namespace std;
class apInfo;
static unordered_map<string, apInfo*>* apManager = new unordered_map<string, apInfo*>;
static unordered_map<string, apInfo*>::iterator apIter;

class apInfo{
private:
    string bssid;
    char essid[32];
    int beaconCnt;
    int dataCnt;
    int channel;
    int power;
    char enc[6];
    char cipher[6];
    char auth[6];
protected:
public:
    apInfo();
    virtual ~apInfo();
    void setBssid(string _bssid);
    void setPower(int _power);
    void setChannel(int _channel);
    void setEnc(char *microsofInfo);
    void setCipher(char *rsnInfo);
    void setAuth(char *rsnInfo);
    void setEssid(char _essid[32], int _length);
    void incDataCnt();
    void incBeaconCnt();
    void printBssid();
    void printPower();
    void printBeaconCnt();
    void printDataCnt();
    void printChannel();
    void printEnc();
    void printCipher();
    void printAuth();
    void printEssid();
};



#endif // APINFO_H
