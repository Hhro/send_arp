#include "ether.h"

Ethernet::Ethernet(uint8_t *dst, uint8_t *src, uint8_t *proto){
    memcpy(h_dest,dst,ETH_ALEN);
    memcpy(hsource,src,ETH_ALEN);
    h_proto=proto;
}