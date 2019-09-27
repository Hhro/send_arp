#pragma once

#include "ether.h"
#include "arp.h"
#include "xpkt.h"

#define CATCH   true
#define FAIL    false

bool filter_IP(pktbyte *pkt);
bool filter_ARP(pktbyte *pkt);
bool filter_ARP_req(pktbyte *pkt);
bool filter_ARP_reply(pktbyte *pkt);