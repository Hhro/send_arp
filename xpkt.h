#pragma once

#include <cstdlib>
#include <cstring>

#define INIT_SIZE 512

class Xpkt{
    private:
        char *buf;
        int len;
        int capacity;

    public:
        Xpkt();
        Xpkt(char *_buf, int len);
        char *get_buf();
        int get_len();
        int get_capacity();
        void set_buf(char *data, int size);
        Xpkt operator + (Xpkt &p);
};