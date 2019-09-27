#pragma once

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#define ALL      -1

#define BYTE      1
#define WORD      2

#define INIT_SIZE 256

#define WPTR_TO_BPTR(WPTR)  (reinterpret_cast <pktbyte *>(WPTR))

typedef uint8_t pktbyte;
typedef uint16_t pktword;
typedef uint32_t pktdword;

class Xpkt{
    private:
        pktbyte *pktbuf;
        int len;
        int capacity;

        friend class ARP;
        friend class Ether;

    public:
        Xpkt();
        Xpkt(const Xpkt& xpkt);
        Xpkt(pktbyte *_pktbuf, int len);
        ~Xpkt();
        pktbyte *get_pktbuf();
        int get_len();
        int get_capacity();
        void set_pktbuf(pktbyte *data, int size);
        void expand(int more);
        void append(pktbyte *data, int size);
        void hexdump(int max_len);
        Xpkt operator / (Xpkt &p);
};
