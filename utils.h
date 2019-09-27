#pragma once

#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include "ether.h"
#include "xpkt.h"

void get_dev_info(char *dev, pktbyte *mac, pktbyte *IP);
void print_mac(pktbyte *mac, const char *prefix);
void parse_mac(pktbyte *mac, char* mac_str);
void print_IP(pktbyte *IP, const char *prefix);