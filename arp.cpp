#include "arp.h"

ARPreq::ARPreq(uint8_t *sha, uint8_t *sip, uint8_t *tip){
    ar_hrd = ARPHRD_ETHER;  //Ethernet
    ar_pro = ETH_P_IP;      //IPV4
    ar_hln = 6;
    ar_pln = 4;
    ar_op  = ARPOP_REQUEST;
    
    memcpy(ar_sha, sha, ETH_ALEN);
    memcpy(ar_sip, sip, 4);
    memset(ar_tha, 0xFF, ETH_ALEN); //Broadcase MAC == FF:FF:FF:FF:FF:FF
    memcpy(ar_tip, tip, 4);
}

ARPrepl::ARPrepl(uint8_t *sha, uint8_t *sip, uint8_t *tha, uint8_t *tip){
    ar_hrd = ARPHRD_ETHER;  //Ethernet
    ar_pro = ETH_P_IP;      //IPV4
    ar_hln = 6;
    ar_pln = 4;
    ar_op  = ARPOP_REPLY;

    memcpy(ar_sha, sha, ETH_ALEN);
    memcpy(ar_sip, sip, 4);
    memcpy(ar_tha, tha, ETH_ALEN);
    memcpy(ar_tip, tip, 4);
}