#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <list>
#include <map>
#include <iostream>
#include <sstream>

using namespace std;
int numpackets = 0;
unsigned int minlength = INT_MAX;
unsigned int maxlength = 0;
unsigned int avglength = 0;
struct timeval firstTime;
struct timeval lastTime;
map<string, int> srcMACMap;
map<string, int> destMACMap;
map<string, int> srcIPMap;
map<string, int> destIPMap;
map<string, list<string> > srcARPMap;
map<string, list<string> > dstARPMap;

list<short> srcPortMap;
list<short> destPortMap;

struct ARPhdr
{
    unsigned char sMAC[ETH_ALEN];   // Sender MAC address.
    unsigned char sIP[4];          // Sender IP address.
    unsigned char tMAC[ETH_ALEN];   // Target MAC address.
    unsigned char tIP[4];          // Target IP address.
};

struct my_ip {
	u_int8_t	ip_vhl;		// version header length
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
//	u_int8_t	ip_tos;		// service type
	u_int16_t	ip_len;		// length
//	u_int16_t	ip_id;
	u_int16_t	ip_off;		// fragment offset
//#define	IP_DF 0x4000			// dont fragment flag
//#define	IP_MF 0x2000			// more fragments flag
//#define	IP_OFFMASK 0x1fff		// mask for fragment bits
//	u_int8_t	ip_ttl;
//	u_int8_t	ip_p;		// protocol
//	u_int16_t	ip_sum;
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

bool inList(list<short> lst, short prt) {
	list<short>::iterator itr;
	for(itr = lst.begin(); itr != lst.end(); itr++) {
		if(*itr == prt) return true;
	}
	return false;
}

bool inMap(map<string, int> checkMap, string checkString) {
	return checkMap.find(checkString)!=checkMap.end();
}

void printMAC(const u_char* data, string *str) {
	char chars[3] = "";
    for(int i = 0; i < 6; i++) {
		sprintf(chars, "%.2x", data[i]);
		if(i < 5) {
			sprintf(chars, "%s:", chars);
		}
		(*str).append(chars);
	}
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int len;

    /* jump past the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      printf("Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        printf("bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        printf("\e[m\033[0;32m\e[1m\t\tIP: \e[m\033[0;32m");
        printf("%s ",
                inet_ntoa(ip->ip_src));
        printf("\e[1m%s \e[m\033[0;32m%d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
    }
    
    
    struct iphdr* ipm = (struct iphdr*)(packet+sizeof(struct ether_header));
    char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
    
    string srcIP, dstip; //src and dst ips
    inet_ntop(AF_INET, &(ipm->saddr), srcStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipm->daddr), dstStr, INET_ADDRSTRLEN);
    
    stringstream sstream, dstream; //stream to track src and dst ips
    sstream << srcStr;
    sstream >> srcIP;
   
    if(!inMap(srcIPMap, srcIP)) {
    	srcIPMap.insert(make_pair(srcIP,1));
    } else {
		srcIPMap[srcIP]++;
	}
    
    dstream << dstStr;
    dstream >> dstip;
	if(!inMap(destIPMap, dstip)) {
		destIPMap.insert(make_pair(dstip,1));
	} else {
		destIPMap[dstip]++;
	}

	if(ipm->protocol==IPPROTO_UDP){ //packet has UDP data
        struct udphdr* UDP = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(iphdr));
        short sport = ntohs(UDP->source);
        short dport = ntohs(UDP->dest);
        if(!inList(srcPortMap, sport)) {
			srcPortMap.push_back(sport);
		}
		if(!inList(destPortMap, dport)) {
			destPortMap.push_back(dport);
		}
    }

    return NULL;
}

/* handle ethernet packets */
u_int16_t handle_ethernet
        (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  // net/ethernet.h
    u_short ether_type;

    if (caplen < ETHER_HDR_LEN) {
        printf("Packet length less than ethernet header length\n");
        return -1;
    }

    eptr = (struct ether_header *) packet;//ethernet header
    ether_type = ntohs(eptr->ether_type);

    printf("\e[m\033[0;34m\e[1mETH: \e[m\033[0;34m"); //print SOURCE DEST TYPE LENGTH
    printf("%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    printf("\e[1m%s \e[m\033[0;34m"
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    if (ether_type == ETHERTYPE_IP) //IP packet
    {
        printf("(IP)");
    }else  if (ether_type == ETHERTYPE_ARP) // ARP
    {
        printf("(ARP)");
    }else  if (eptr->ether_type == ETHERTYPE_REVARP) //reverse ARP (probably unnecessary)
    {
        printf("(RARP)");
    } else { //others
        printf("()");
    }
    printf(" %d\n",length);

    return ether_type;
}

/* callback function */
void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    
    struct timeval pkt_time = pkthdr->ts;
	if(numpackets < 1) {
		firstTime = pkt_time;
		time_t timesec = pkt_time.tv_sec;
		struct tm* secinfo = localtime(&timesec);
		printf("CAPTURE START: %s", asctime(secinfo));  //PRINTS START TIME ABOVE PER-PACKET READOUT
	}
	
	printf("\e[m\033[0;32m%ld.%lds\t", pkt_time.tv_sec-firstTime.tv_sec, pkt_time.tv_usec);
	
	struct ether_header* ethernet = (struct ether_header *)packet;
	if(pkthdr->len < minlength){//update shortest packet
		minlength = pkthdr->len;
	}
	if(pkthdr->len > maxlength){//update longest packet
		maxlength = pkthdr->len;
	}
	avglength += pkthdr->len;   //keep track of average packet length
	string shost, dhost;
	printMAC(ethernet->ether_shost, &shost);
	printMAC(ethernet->ether_dhost, &dhost);
	if(!inMap(srcMACMap, shost)) srcMACMap.insert(make_pair(shost,1));
	else srcMACMap[shost]++;
	if(!inMap(destMACMap, dhost)) destMACMap.insert(make_pair(dhost,1));
	else destMACMap[dhost]++;
	
    u_int16_t type = handle_ethernet(args,pkthdr,packet);

    if(type == ETHERTYPE_IP)
    {// handle IP packet
        handle_IP(args,pkthdr,packet);
    }else if(type == ETHERTYPE_ARP)
    {// handle ARP packet
    	string shostmac, dhostmac, shostip, dhostip;
		struct ARPhdr* arp = (struct ARPhdr*)(packet+sizeof(struct ether_header)+sizeof(struct arphdr));
		printMAC(arp->sMAC, &shostmac);
		printMAC(arp->tMAC, &dhostmac);
		//get ip addresses
		char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(arp->sIP), srcStr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(arp->tIP), dstStr, INET_ADDRSTRLEN);
		stringstream sstream, dstream;
		sstream << srcStr;
        sstream >> shostip;
        dstream << dstStr;
        dstream >> dhostip;
		//make ip lists
		if(srcARPMap.find(shostmac)!=srcARPMap.end()){
		    (srcARPMap[shostmac]).push_back(shostip);
		} else {
		    list<string> ARPsips;
		    ARPsips.push_back(shostip);
		    srcARPMap.insert(make_pair(shostmac,ARPsips));
		}
		if(dstARPMap.find(dhostmac)!=dstARPMap.end()){
		    (dstARPMap[dhostmac]).push_back(dhostip);
		} else {
		    list<string> ARPdips;
		    ARPdips.push_back(dhostip);
		    dstARPMap.insert(make_pair(dhostmac,ARPdips));
		}
    }
    else if(type == ETHERTYPE_REVARP)
    {//Don't handle reverse ARP to prevent crash
    }
    
	numpackets++;
	lastTime = pkt_time;
	//printf("Received packet at time %ld %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
	//printf("%f", pkt_time.tv_sec + pkt_time.tv_usec);
    
}

void printSList(list<short> prnt) {
	prnt.sort();
	list<short>::iterator itr;
	for(itr = prnt.begin(); itr != prnt.end(); itr++) {
		cout << *itr << endl;
	}
	cout << endl;
}

void printMap(map<string, int> prnt) {
	map<string, int>::iterator itr;
	for(itr = prnt.begin(); itr != prnt.end(); itr++) {
		cout << (*itr).first << "\t(  " << (*itr).second << "\tpackets)" << endl;
	}
	cout << endl;
}

void printIPList(map<string, list<string> > prnt) {
	map<string, list<string> >::iterator itrMap;
	list<string>::iterator itrList;
	list<string> tempList;
	for(itrMap = prnt.begin(); itrMap != prnt.end(); itrMap++) {
		cout << (*itrMap).first << endl;
		tempList = (*itrMap).second;
		tempList.sort();
		tempList.unique();
		for(itrList = tempList.begin(); itrList != tempList.end(); itrList++) {
			cout << "\e[m\t" << *itrList << "\n\e[m\033[0;32m";
		}
	}
	cout << endl;
}


int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     // pcap.h
    struct ether_header *eptr;  // net/ethernet.h
	
	system("clear");
    if(argc != 3){ printf("Usage: %s numPackets fileName\nUse (numPackets = -1) for all packets in file.\n",argv[0]);return 0;}

    //open pcap dump file
    descr = pcap_open_offline(argv[2],errbuf);
    if(descr == NULL)
    { printf("pcap_open_offline(): %s\n",errbuf); exit(1); }
    
    int linkType = pcap_datalink(descr);
    printf("Capture link-layer header is of type: ");
    if (linkType == 1){
    	printf("LINKTYPE_ETHERNET\n\n");
    	pcap_loop(descr,atoi(argv[1]),my_callback,NULL);
    	puts("\e[m\nFinished reading packets from file.");
    } else {
    	printf("not ethernet\n\n");
    }
    
    pcap_close(descr);
    
    puts("Closed File.\n");
    
    if(!srcMACMap.empty()) {
    	printf("\e[m\033[0;31m\e[1mUnique Ethernet Sources:\n\e[m\033[0;32m");
		printMap(srcMACMap);
	}
    if(!destMACMap.empty()) {
    	printf("\e[m\033[0;31m\e[1mUnique Ethernet Destinations:\n\e[m\033[0;32m");
		printMap(destMACMap);
	}
    if(!srcIPMap.empty()) {
    	printf("\e[m\033[0;31m\e[1mUnique IP Sources:\n\e[m\033[0;32m");
		printMap(srcIPMap);
	}
    if(!destIPMap.empty()) {
    	printf("\e[m\033[0;31m\e[1mUnique IP Destinations:\n\e[m\033[0;32m");
		printMap(destIPMap);
	}
	if(!srcARPMap.empty()) {
		printf("\e[m\033[0;31m\e[1mUnique ARP Sources:\n\e[m\033[0;32m");
		printIPList(srcARPMap);
	}
	if(!dstARPMap.empty()) {
		printf("\e[m\033[0;31m\e[1mUnique ARP Destinations:\n\e[m\033[0;32m");
		printIPList(dstARPMap);
	}
    if(!srcPortMap.empty()) {
    	printf("\e[m\033[0;31m\e[1mUnique UDP Source Ports:\n\e[m\033[0;32m");
		printSList(srcPortMap);
	}
	if(!destPortMap.empty()) {
		printf("\e[m\033[0;31m\e[1mUnique UDP Destination Ports:\n\e[m\033[0;32m");
		printSList(destPortMap);
	}
	
	avglength = avglength / numpackets;
	printf("\e[m\033[0;32m\e[1mMinimum packet length: \e[m%d bytes\n\e[m\033[0;32m\e[1mMaximum packet length: \e[m%d bytes\n\033[0;35m\e[1m\tAverage packet length: \e[m%d bytes\n", minlength, maxlength, avglength);
    
    return 0;
}
