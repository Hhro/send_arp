#pragma once

#include <cstring>
#include <cstdint>
#include <pcap.h>

class ARP{
    private:
        uint16_t  ar_hrd;
        uint16_t  ar_pro;
        uint8_t ar_hln;
        uint8_t ar_pln;
        uint16_t  ar_op;
        uint8_t ar_sha[ETH_ALEN];
        uint8_t ar_sip[4];
        uint8_t ar_tha[ETH_ALEN];
        uint8_t ar_tip[4]; 
    
    public:
        ARP(uint8_t *pkt);
};

class ARPreq : public ARP {
    public:
        ARPreq(uint8_t *sha, uint8_t *sip, uint8_t *tip);
};

class ARPrepl : public ARP {
    public:
        ARPrepl(uint8_t *sha, uint8_t * sip, uint8_t * tha, uint8_t *tip);
};
