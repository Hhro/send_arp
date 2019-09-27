#pragma once

#include <cstring>
#include <cstdint>
#include <pcap.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include "ether.h"
#include "xpkt.h"


/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK	10		/* (ATM)ARP NAK			*/

#define ARP_(pkt)    (reinterpret_cast<struct arphdr *>(pkt + ETH_HLEN))

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
};

class ARP : public Xpkt{
    private:
        pktword  ar_hrd;
        pktword  ar_pro;
        pktbyte  ar_hln;
        pktbyte  ar_pln;
        pktword  ar_op;
        pktbyte  ar_sha[ETH_ALEN];
        pktbyte  ar_sip[4];
        pktbyte  ar_tha[ETH_ALEN];
        pktbyte  ar_tip[4]; 

    public:
        ARP(Xpkt xpkt);
        ARP(pktword op, pktbyte *sha, pktbyte *sip, pktbyte *tha, pktbyte *tip);
        pktword get_pro();
        pktword get_op();
        pktbyte* get_sha();
        pktbyte* get_tha();
        void assemble();
        void dissect();
};