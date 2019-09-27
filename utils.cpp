#include "utils.h"

/*
http://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/2
*/
void get_dev_info(char *dev, pktbyte *mac, pktbyte *IP)
{
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(IP, ifr.ifr_addr.sa_data + 2, 4);
}

void print_mac(pktbyte *mac, const char *prefix){
    if(prefix){
        std::cout << prefix;
    }
    std::cout << "MAC: ";

    for(int i=0; i < ETH_ALEN; i++){
        std::cout 
        << std::hex 
        << std::setw(2) 
        << std::setfill('0') 
        << static_cast<int>(mac[i]);
        
        if(i != ETH_ALEN-1){
            std::cout << ":";
        }
    }
    std::cout << std::endl;
}

void parse_mac(pktbyte *mac, char *mac_str){
    for(int i=0; i< ETH_ALEN; i++){
        sprintf(mac_str+3*i, "%02X", mac[i]);

        if(i!=ETH_ALEN-1)
            strcat(mac_str,":");
    }
}

void print_IP(pktbyte *IP, const char *prefix){
    char IP_str[20];

    if(prefix){
        std::cout << prefix;
    }

    inet_ntop(AF_INET, IP, IP_str, sizeof(IP_str));
    std::cout << "IP: " << IP_str;
}