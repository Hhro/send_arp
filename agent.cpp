#include "agent.h"

Agent::Agent(){
}

Agent::Agent(uint8_t *_mac, uint8_t *_IP){
    memcpy(this->mac, _mac, ETH_ALEN);
    memcpy(this->IP, _IP, 4);
}

void Agent::set_mac(uint8_t *_mac){
    memcpy(this->mac, _mac, ETH_ALEN);
}

void Agent::set_IP(uint8_t *_IP){
    memcpy(this->IP, _IP, 4);
}

int Agent::send(char *dev, uint8_t *pkt, int pkt_sz){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    int res;

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        return -1;
    }

    if(!pcap_inject(handle, pkt, pkt_sz)){
        pcap_perror(handle, "send: ");
        return -1;
    }

    return 0;
}