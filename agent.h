#pragma once

#include <iostream>
#include <cstring>
#include <cstdint>
#include <pcap.h>
#include "ether.h"

class Agent{
    private:
        uint8_t mac[ETH_ALEN];
        uint8_t IP[4];
    
    public:
        Agent();
        Agent(uint8_t *_mac, uint8_t *_IP);
        void set_mac(uint8_t *_mac);
        void set_IP(uint8_t *_IP);
        int send(char *dev, uint8_t *pkt, int pkt_sz);
        //void send_arp(uint8_t *dev, uint16_t sender, uint16_t target);
};
