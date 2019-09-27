#pragma once

#include <cstring>
#include <cstdint>

#define ETH_ALEN    6

class Ethernet{
    private:
        uint8_t h_dest[ETH_ALEN];
        uint8_t hsource[ETH_ALEN];
        uint16_t  h_proto;

    public:
        Ethernet(uint8_t *dst, uint8_t *src, uint8_t *proto);
};
