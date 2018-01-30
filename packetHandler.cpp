#include <pcap.h>
#include <iostream>
#include <regex>
#include <iomanip>
#include <ctime>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include "packetHandler.h"
#include "dot11.h"
#include "dump.h"

using namespace std;

packetHandler::packetHandler(char INTERFACE[16])
{
    strncpy(this->interface, INTERFACE, 16);
    tmpCheck = 0;
    ggomsu = 0;
}

packetHandler::~packetHandler(){}

void packetHandler::checkInterface()
{
    pcap_if_t *devs;
    int check = 0;

    // *****************************
    // Check device
    // *****************************
    if (-1 == pcap_findalldevs(&devs, errbuf))
    {
        cout << "Couldn't open device list: " << errbuf << endl;
        exit(1);
    }
    if (!devs) {
        cout << "No devices found." << endl;
        exit(1);
    }
    for (pcap_if_t *d = devs; d; d = d->next) {
        if(!strcmp(d->name, interface))
            check++;
    }
    pcap_freealldevs(devs);

    // *****************************
    // Error! Check usage plz!
    // *****************************
    if(!check){
        cout << "\033[1;31mError : interface is not exist... Check it plz.\033[0m" << endl;
        cout << "\033[1;32m Usage: airodump <Interface>\033[0m" << endl <<\
                "\033[1;31m Ex) airodump mon0\033[0m\n";
        exit(1);
    }
    else
        cout << "\033[1;34m OK! Your device name is \033[0m" << interface << endl;

    // *****************************
    // Check monitor mode
    // *****************************


    // *****************************
    // Check pcap
    // *****************************
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }
}

std::thread packetHandler::hopping()
{
    char cmd[100];
    nowChannel = rand()%13 + 1;
    ggomsu += 10;
    if(ggomsu > 100){
        sprintf(cmd, "iwconfig %s channel %d", this->interface, nowChannel);
        system(cmd);
        ggomsu = 0;
    }
}

void packetHandler::findTag(const char *tag, int pktLength, apInfo *ap)
{
    tagMetadata *tm;
    const char *currentLocation = tag;
    int totalLength = 0;

    dumping dmp;
    while(totalLength < pktLength)
    {
        tm = (tagMetadata *)currentLocation;
        switch((int)(tm->type))
        {
        case 0x00:
            ap->setEssid((char *)(currentLocation + sizeof(tagMetadata)), (int)(tm->length));
            break;
        case 0x03:
            ap->setChannel((int)((currentLocation + sizeof(tagMetadata))[0]));
            break;
        case 0x30:
            ap->setCipher((char *)currentLocation);
            ap->setAuth((char*)currentLocation);
            break;
//        case 0xdd:
//            ap->setEnc((char *)currentLocation);
        }
        currentLocation += sizeof(tagMetadata) + (int)(tm->length);
        totalLength += sizeof(tagMetadata) + (int)(tm->length);
    }
}

void packetHandler::capture()
{
    while(true){
        hopping();
        packetHandler::printAll();
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 1){
            parser(packet);
        }
        else{
            continue;
        }
    }
}

void packetHandler::parser(const u_char *pkt)
{
    radioTapHeader *rth;
    ieeeDot11Frame *idf;
    apInfo *ap;
    string _bssid;
    string _staid;

    rth = (radioTapHeader *)pkt;
    idf = (ieeeDot11Frame *)(pkt + rth->length);
    switch(idf->typeInfo){
    // Beacon Frame
    case '\x00\x80':
//        beaconFrame *bf = (beaconFrame *)(pkt + rth->length + sizeof(ieeeDot11Frame));
//        tagMetadata *tmd = (tagMetadata *)(pkt + rth->length + sizeof(ieeeDot11Frame) + sizeof(beaconFrame));

        // limit bssid[6]
        _bssid = (char *)idf->addr3;
        _bssid.erase(_bssid.begin()+6, _bssid.end());

        // check isSameKey()
        apIter = apManager->find(_bssid);

        // insert to map
        if( apIter != apManager->end())
        {
            apIter->second->incBeaconCnt();
        }
        else
        {
            ap = new apInfo();
            ap->setBssid(_bssid);
            // insert tag info
            findTag((const char *)(pkt + rth->length + sizeof(ieeeDot11Frame) + sizeof(beaconFrame)),\
                    header->len - rth->length - sizeof(beaconFrame)-24,\
                    ap);
            // insert power info ( SSI Signal )
            ap->setPower((int)(pkt + rth->length - 2)[0]);
            apManager->insert(unordered_map<string, apInfo*>::value_type(_bssid, ap));
        }
        break;
    // QoS Data
    case '\x42\x88':
        _bssid = (char *)idf->addr2;
        _bssid.erase(_bssid.begin()+6, _bssid.end());
        apIter = apManager->find(_bssid);
        if( apIter != apManager->end())
        {
            apIter->second->incDataCnt();
        }
        break;
    // Probe Request
    case '\x00\x04':
        _staid = (char *)idf->addr1;
        _staid.erase(_staid.begin()+6, _staid.end());

        _bssid = (char *)idf->addr3;
        _bssid.erase(_bssid.begin()+6, _bssid.end());
        // send Deauthentication Packet
        // deauchPacket(_bssid, _staid);
    }
}

void packetHandler::deauthPacket(string _bssid, string _staid)
{
    char deauthPkt[38];
    // radio tap header start
    deauthPkt[0] = '\x00'; // header revision
    deauthPkt[1] = '\x00'; // header pad
    strncpy(deauthPkt+2, "\x0b\x00", 2); // Header Length
    strncpy(deauthPkt+4, "\x00\x80\x02\x00", 4); // Present Flags
    strncpy(deauthPkt+8, "\x00\x00\x00", 3); // padding
    // radio tap header end

    deauthPkt[11] = '\xc0';
    deauthPkt[12] = '\x00';
    strncpy(deauthPkt+13, "\x00\x00", 2);
    strncpy(deauthPkt+15, _staid.c_str(), 6);
    strncpy(deauthPkt+21, _bssid.c_str(), 6);
    strncpy(deauthPkt+27, _bssid.c_str(), 6);
    strncpy(deauthPkt+33, "\x00\x00", 2); // sequence number

    strncpy(deauthPkt+35, "\x08\x00", 2); // IEEE 802.11 wireless LAN management frame
}

void packetHandler::printAll()
{
    time_t now = time(0);
    char *dt = ctime(&now);

    system("clear");
    cout << endl << " CH " << left << setw(3) << nowChannel;
    cout << "[ " << dt << endl;

    // subject
    cout << "     "
         << left << setw(20) << "       BSSID"
         << left << setw(5) << "PWR"
         << left << setw(5) << "BC#"
         << left << setw(8) << "Data#"
         << left << setw(5) << "CH#"
         << left << setw(6) << "ENC"
         << left << setw(8) << "CIPHER"
         << left << setw(6) << "AUTH"
         << left << setw(32) << "ESSID"
         << endl;

    for( apIter = apManager->begin(); apIter != apManager->end(); apIter++){
        cout << "     ";
        apIter->second->printBssid();
        cout << "   ";
        apIter->second->printPower();
        apIter->second->printBeaconCnt();
        apIter->second->printDataCnt();
        apIter->second->printChannel();
        apIter->second->printEnc();
        apIter->second->printCipher();
        apIter->second->printAuth();
        apIter->second->printEssid();
        cout << endl;
    }
}

std::thread packetHandler::dump()
{
    packetHandler::checkInterface();
    packetHandler::capture();
}


