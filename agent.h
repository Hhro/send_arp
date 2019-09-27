#pragma once

#include <iostream>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <thread>
#include <pcap.h>
#include "arp.h"
#include "ether.h"
#include "utils.h"
#include "filter.h"
#include "xpkt.h"

class Agent{
    private:
        char dev[0x100];        //Linux: max length of file name == 0xff
        pktbyte mac[ETH_ALEN];
        pktbyte IP[4];
    
    public:
        Agent(char *dev);

        pktbyte* get_IP();
        pktbyte* get_mac();

        void show_info();

        int send(char *dev, Xpkt *pkt);
        void snatch(char *dev, Xpkt *pkt, bool (*filter)(pktbyte *pkt));

        int arp_send_req(char *dev, pktbyte *target);
        //int send_arp_repl(char *dev, pktbyte *target);
        int arp_send_raw(
            char *dev, 
            pktword op, 
            pktbyte *sha, 
            pktbyte *sip, 
            pktbyte *tha, 
            pktbyte *tip
        );
        int arp_get_target_mac(char *dev, pktbyte *target, pktbyte *mac);
        int arp_spoof(char *dev, pktbyte *sender, pktbyte *target);

};
