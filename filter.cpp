#include "filter.h"

bool filter_IP(pktbyte *pkt){
    ethhdr *ethernet = ETHERNET_(pkt);

    if(ethernet->h_proto == htons(ETH_P_IP)){
        return CATCH;
    }

    return FAIL;
}

bool filter_ARP(pktbyte *pkt){
    ethhdr *ethernet = ETHERNET_(pkt);

    if(ethernet->h_proto == htons(ETH_P_ARP)){
        return CATCH;
    }
    
    return FAIL;
}

bool filter_ARP_req(pktbyte *pkt){
    ethhdr *ethernet = ETHERNET_(pkt);

    if(ethernet->h_proto != htons(ETH_P_ARP))
        return FAIL;

    arphdr *arp = ARP_(pkt);

    if(arp->ar_op == htons(ARPOP_REQUEST))
        return CATCH;
    
    return FAIL;
}

bool filter_ARP_reply(pktbyte *pkt){
    ethhdr *ethernet = ETHERNET_(pkt);

    if(ethernet->h_proto != htons(ETH_P_ARP))
        return FAIL;

    arphdr *arp = ARP_(pkt);

    if(arp->ar_op == htons(ARPOP_REPLY))
        return CATCH;
    
    return FAIL;
}