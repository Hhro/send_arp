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

#define MAXDEV     0x100
#define MAXMACSTR  0x15
#define MAXIPSTR   0x12

class Agent{
    private:
        char dev[MAXDEV+1];        
        pktbyte_n mac[ETH_ALEN+1];
        char mac_str[MAXMACSTR+1];
        pktbyte_n ip[4+1];
        char ip_str[MAXIPSTR+1];
    
    public:
        Agent();
        Agent(char *dev);

        char* get_dev();
        pktbyte_n* get_mac();
        char* get_mac_str();
        pktbyte_n* get_ip();
        char* get_ip_str();

        void set_mac(pktbyte_n *_mac);
        void set_ip_str(char *_ip_str);

        void show_info();

        int send(Xpkt *pkt);
        void snatch(Xpkt *pkt, bool (*filter)(pktbyte_n *pkt));

        void arp_send_req(Agent *target);
        //int arp_send_reply(char *dev, pktbyte *target);
        int arp_send_raw(
            pktword_h op, 
            pktbyte_n *sha, 
            pktbyte_n *sip, 
            pktbyte_n *tha, 
            pktbyte_n *tip
        );
        int arp_get_target_mac(Agent *target);
        int arp_spoof(Agent *sender, Agent *target);

};
