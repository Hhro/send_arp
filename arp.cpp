#include "arp.h"

ARP::ARP(Xpkt xpkt) : Xpkt(xpkt){
    ARP::dissect();
}

ARP::ARP(pktword op, pktbyte *sha, pktbyte *sip, pktbyte *tha, pktbyte *tip){
    ar_hrd = htons(ARPHRD_ETHER);  //Ethernet
    ar_pro = htons(ETH_P_IP);      //IPV4
    ar_hln = 6;
    ar_pln = 4;
    ar_op = htons(op);

    memcpy(ar_sha, sha, ETH_ALEN);
    memcpy(ar_sip, sip, 4);
    memcpy(ar_tha, tha, ETH_ALEN);
    memcpy(ar_tip, tip, 4);

    ARP::assemble();
}

pktword ARP::get_pro(){
    return ar_pro;
}

pktword ARP::get_op(){
    return ar_op;
}

pktbyte* ARP::get_sha(){
    return ar_sha;
}

pktbyte* ARP::get_tha(){
    return ar_tha;
}

void ARP::assemble(){
    ARP::append(WPTR_TO_BPTR(&ar_hrd), WORD);
    ARP::append(WPTR_TO_BPTR(&ar_pro), WORD);
    ARP::append(&ar_hln, BYTE);
    ARP::append(&ar_pln, BYTE);
    ARP::append(WPTR_TO_BPTR(&ar_op), WORD);
    ARP::append(ar_sha, ETH_ALEN);
    ARP::append(ar_sip, 4);
    ARP::append(ar_tha, ETH_ALEN);
    ARP::append(ar_tip, 4);
}

void ARP::dissect(){
    arphdr *arp = ARP_(pktbuf); 
    ar_hrd = arp->ar_hrd;
    ar_pro = arp->ar_pro;
    ar_hln = arp->ar_hln;
    ar_pln = arp->ar_pln;
    ar_op = arp->ar_op;

    memcpy(ar_sha, arp->ar_sha, ETH_ALEN);
    memcpy(ar_sip, arp->ar_sip, 4);
    memcpy(ar_tha, arp->ar_tha, ETH_ALEN);
    memcpy(ar_sip, arp->ar_sip, 4);
}