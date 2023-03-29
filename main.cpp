#include <cstdio>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle;
Mac myMac, senderMac;
Ip myIp, senderIp, targetIp;
EthArpPacket packet;

Mac broadcast = Mac("ff:ff:ff:ff:ff:ff");
Mac unknown = Mac("00:00:00:00:00:00");

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getmyMac(Mac *myMac, char *inter)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "fail to make socket!\n");
		close(fd);
		return false;
	}

	strncpy(ifr.ifr_name, inter, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "fail to get myMac!\n");
		close(fd);
		return false;
	}

	uint8_t socketMac[Mac::SIZE];
	memcpy(socketMac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	*myMac = Mac(socketMac);

	close(fd);
	return true;
}

bool getmyIp(Ip *myIp, char *inter)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "fail to make socket!\n");
		close(fd);
		return false;
	}

	strncpy(ifr.ifr_name, inter, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "fail to get myIp!\n");
		close(fd);
		return false;
	}

	*myIp = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	close(fd);
	return true;
}

void makepacket(EthArpPacket *packet, Mac smac, Mac dmac, Ip sip, Ip dip, bool type)
{
	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.smac_ = smac;
	packet->arp_.sip_ = htonl(sip);
	packet->arp_.tip_ = htonl(dip);

	if (type) {
		packet->arp_.op_ = htons(ArpHdr::Request);
		packet->arp_.tmac_ = unknown;
	}
	else {
		packet->arp_.op_ = htons(ArpHdr::Reply);
		packet->arp_.tmac_ = dmac;
	}

	return;
}

bool getsenderMac(Mac *senderMac, Ip senderIp, char *inter)
{
	for(;;) {
		makepacket(&packet, myMac, broadcast, myIp, senderIp, true);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return false;
		}

		struct pcap_pkthdr *pkthdr;
		const u_char *reply;
		res = pcap_next_ex(handle, &pkthdr, &reply);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return false;
		}

		EthArpPacket *replyPacket = (EthArpPacket*)reply;
		uint8_t replyMac[Mac::SIZE];
		memcpy(replyMac, &replyPacket->arp_.smac_, Mac::SIZE);
		*senderMac = Mac(replyMac);
		return true;
	}
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	if(!getmyMac(&myMac, dev)) return -1;
	if(!getmyIp(&myIp, dev)) return -1;
	senderIp = Ip(argv[2]);
	targetIp = Ip(argv[3]);
	getsenderMac(&senderMac, senderIp, dev);

	makepacket(&packet, myMac, senderMac, targetIp, senderIp, false);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else fprintf(stderr, "send packet success!\n");

	pcap_close(handle);
}
