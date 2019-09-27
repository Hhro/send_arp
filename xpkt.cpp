#include <cstdio>
#include "xpkt.h"

Xpkt::Xpkt(){
    buf = (char *)malloc(sizeof(char)*INIT_SIZE);
    memset(buf, 0, INIT_SIZE);
    len = 0;
    capacity = INIT_SIZE;
}

Xpkt::Xpkt(char *_buf, int _len){
    Xpkt();
    set_buf(_buf,_len);
}

char* Xpkt::get_buf(){
    return buf;
}

int Xpkt::get_len(){
    return len;
}

int Xpkt::get_capacity(){
    return capacity;
}

void Xpkt::set_buf(char *data, int size){
    int _capacity;

    if(size >= capacity){
        _capacity = INIT_SIZE * (capacity / INIT_SIZE + 1);
        buf = (char *)realloc(buf, _capacity);
        capacity = _capacity;
    }

    memset(buf, 0, capacity);
    memcpy(buf, data, size);
    len = size;
}

Xpkt Xpkt::operator + (Xpkt &p){
    int _len = len + p.get_len();
    char *_buf = (char *)malloc(sizeof(char) * (_len + 1));

    memset(_buf, 0, _len);
    
    memcpy(_buf, buf, len);
    memcpy(_buf + len, p.buf, p.len);

    return Xpkt(_buf, _len);
}