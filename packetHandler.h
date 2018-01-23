#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H
#include <pcap.h>
#include "dot11.h"
#include "apInfo.h"
#include "dump.h"

class packetHandler{
private:
    pcap_t *handle;         /* Session handle */
    struct bpf_program fp;      /* The compiled filter */
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    int res;
    char interface[16];
    int nowChannel;
protected:
    const u_char *packet;       /* The actual packet */
    int tmpCheck;
public:
    packetHandler(char INTERFFACE[16]);
    virtual ~packetHandler();
    void checkInterface();
    void findTag(const char *tag, int pktLength, apInfo *ap);
    void capture();
    void hopping();
    void parser(const u_char *pkt);
    void deauthPacket(string _bssid, string _staid);
    void printAll();
    void dump();
};

#endif // PACKET_HANDLER_H

