
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

uint16_t arpValue = 0x0806;
uint16_t ipV4Value = 0x0800;
queue coada;
struct arp_entry arp_table[10000];
int arptTableLen = 0;

struct route_table_entry *rtable;
int sizeOfRtable;

uint8_t broadcast[6];

struct pachet
{
	char buf[MAX_PACKET_LEN];
	int len;
};

char *afisareInHumanReadeableIp(uint32_t ip)
{
	char adresaIp[16];
	uint32_t copieIp = ip;
	inet_ntop(2, &copieIp, adresaIp, sizeof(adresaIp));

	char *ret = malloc(16);
	memcpy(ret, adresaIp, 16);
	return ret;
}
struct route_table_entry *get_best_route_Binary_Search(uint32_t ip_dest, int rtable_len, struct route_table_entry *rtable)
{
	int left = 0;
	int right = rtable_len;
	struct route_table_entry *solutie = NULL;
	ip_dest = ntohl(ip_dest);

	while (left <= right)
	{
		int mid = (left + right) / 2;

		if ((ip_dest & ntohl(rtable[mid].mask)) == ntohl(rtable[mid].prefix))
		{
			if (solutie == NULL || ntohl(solutie->mask) < ntohl(rtable[mid].mask))
			{
				solutie = &rtable[mid];
			}
			left++;
		}
		else
		{
			if (ip_dest >= ntohl(rtable[mid].prefix))
				left = mid + 1;
			else
				right = mid - 1;
		}
	}

	return solutie;
}

struct arp_entry *get_Arp_Entry_fromArpTable(struct arp_entry *table, int len, uint32_t ipDest)
{
	struct arp_entry *best = NULL;
	for (int i = 0; i < len; i++)
	{
		if (table[i].ip == ipDest)
		{
			return &table[i];
		}
	}
	return best;
}
int areDifferentMacAddresses(uint8_t first[6], uint8_t second[6])
{
	for (int k = 0; k < 6; k++)
	{
		if (first[k] != second[k])
			return 1;
	}
	return 0;
}
void conversieNtohlRouteTable(struct route_table_entry *a)
{
	a->mask = ntohl(a->mask);
	a->prefix = ntohl(a->prefix);
}
void conversieHtonlRouteTable(struct route_table_entry *a)
{
	a->mask = htonl(a->mask);
	a->prefix = htonl(a->prefix);
}
int compareRouteTableEntry(const void *a, const void *b)
{
	struct route_table_entry *prima = (struct route_table_entry *)a;
	struct route_table_entry *doua = (struct route_table_entry *)b;

	if (prima->prefix == doua->prefix)
	{
		if (prima->mask > doua->mask)
			return 1;
		else
			return -1;
	}
	else
	{
		if (prima->prefix > doua->prefix)
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}
}
void sortareRoutingTable(struct route_table_entry *rtable, int rtable_len)
{
	/// convertesc masca si prefixul la host order
	for (int i = 0; i < rtable_len; i++)
		conversieNtohlRouteTable(&rtable[i]);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compareRouteTableEntry);

	/// convertesc masca si prefixul la network order la loc
	for (int i = 0; i < rtable_len; i++)
		conversieHtonlRouteTable(&rtable[i]);
}
void generareIcmpPartial(char *packet, char *buf, int code, int type, int interface)
{
	/// cele vechi
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	/// creez un nou ether header
	struct ether_header *eth_hdrIcmp = malloc(sizeof(struct ether_header));
	memcpy(eth_hdrIcmp->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdrIcmp->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_shost));
	eth_hdrIcmp->ether_type = htons(ipV4Value);
	/// creez un nou ip header
	struct iphdr *iphdrIcmp = malloc(sizeof(struct iphdr));
	iphdrIcmp->check = 0;
	iphdrIcmp->version = 4;
	iphdrIcmp->ihl = 5;
	iphdrIcmp->tos = 0;
	iphdrIcmp->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8); // pt ttl si unreacheable
	iphdrIcmp->id = htons(1);
	iphdrIcmp->frag_off = 0;
	iphdrIcmp->ttl = 64;
	iphdrIcmp->protocol = 1;
	iphdrIcmp->saddr = (uint32_t)inet_addr(get_interface_ip(interface));
	iphdrIcmp->daddr = ip_hdr->saddr;
	/// calculez checksumul dupa setarea campurilor
	iphdrIcmp->check = htons(checksum((uint16_t *)iphdrIcmp, sizeof(struct iphdr)));

	struct icmphdr *icmpHeader = malloc(sizeof(struct icmphdr));
	icmpHeader->type = type;
	icmpHeader->code = code;
	/// id ul si sequence ar putea primi un algoritm
	icmpHeader->un.echo.id = 1;
	icmpHeader->un.echo.sequence = 1;

	icmpHeader->checksum = 0;
	icmpHeader->checksum = htons(checksum((uint16_t *)icmpHeader, sizeof(struct icmphdr)));
	/// adaug toate headerele in noul packet
	memcpy(packet, eth_hdrIcmp, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), iphdrIcmp, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmpHeader, sizeof(struct icmphdr));
}
int generareIcmpContinuare(char *packet, char *buf)
{
	/// aceasta functie adauga vechiul iphdr si primii 64 de biti din payload
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	int ant = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	memcpy(packet + ant, ip_hdr, sizeof(struct iphdr));
	memcpy(packet + ant + sizeof(struct iphdr), buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

	struct icmphdr *cchk = (struct icmphdr *)(packet + ant - sizeof(struct icmphdr));
	/// recalculez checksumul icmphdr
	cchk->checksum = 0;
	cchk->checksum = htons(checksum((uint16_t *)cchk, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));
	/// returnez dimensiunea
	return ant;
}
int generareICMPTtlUnreacheable(char *packet, char *buf, int code, int type, int interface)
{
	/// generez pachetul ICMP pentru TTL sau Destination Unreacheable
	/// pachetul este asemenea in schimb codul este diferit
	generareIcmpPartial(packet, buf, code, type, interface);

	int skip = generareIcmpContinuare(packet, buf);

	return (skip + sizeof(struct iphdr) + 8);
}
void trimite(struct ether_header *eth_hdr, struct arp_entry *nextHop, int len)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(struct ether_header));
	struct route_table_entry *next = get_best_route_Binary_Search(ip_hdr->daddr, sizeOfRtable, rtable);
	memcpy(eth_hdr->ether_dhost, nextHop->mac, sizeof(nextHop->mac));

	send_to_link(next->interface, (char *)eth_hdr, len);
}
void trimitereRestante()
{
	/// functia incearca sa trimita toate pachetele care au MAC si IP gasite
	/// in tabela ARP
	queue temp;
	temp = queue_create();

	while (!queue_empty(coada))
	{
		struct pachet *packet = queue_deq(coada);
		struct ether_header *ether_header = (struct ether_header *)(packet->buf);
		struct iphdr *ip_hdr = (struct iphdr *)((char *)ether_header + sizeof(struct ether_header));

		struct route_table_entry *next = get_best_route_Binary_Search(ip_hdr->daddr, sizeOfRtable, rtable);
		uint8_t macMeu[6];
		get_interface_mac(next->interface, macMeu);

		memcpy(ether_header->ether_shost, macMeu, 6);

		struct arp_entry *nextHop = NULL;
		nextHop = get_Arp_Entry_fromArpTable(arp_table, arptTableLen, next->next_hop);
		/// daca nu gasesc intrarea adaug in coada auxiliara temp
		if (nextHop == NULL)
		{
			queue_enq(temp, (void *)ether_header);
		}
		else
		{
			/// apel functia de send
			trimite(ether_header, nextHop, packet->len);
		}
	}
	/// adaug tot ce nu si a gasit in tabela ARP in coada de asteptare
	while (!queue_empty(temp))
	{
		queue_enq(coada, queue_deq(temp));
	}
}
void processArp(struct ether_header *eth_hdr, int interface, size_t len)
{
	struct arp_header *arp_header = (struct arp_header *)(((char *)eth_hdr) + sizeof(struct ether_header));

	/// daca e arp reply
	if (ntohs(arp_header->op) == 2)
	{
		/// am primit o combinatie MAC IP noua, o salvez si caut in toate
		/// pachetele restante daca il ajuta noua combinatie primita 
		struct arp_entry arp_entry;
		memcpy(arp_entry.mac, arp_header->sha, 6);
		arp_entry.ip = arp_header->spa;
		arp_table[arptTableLen] = arp_entry;
		arptTableLen++;

		/// daca e goala n are sens sa mai caut
		if (!queue_empty(coada))
			trimitereRestante();
	}
	else if (arp_header->tpa == inet_addr(get_interface_ip(interface)))
	{
		/// daca eu sunt destinatia, raspund cu MAC ul meu
		/// trimit un pachet ARP reply la un request
		char packet[MAX_PACKET_LEN];

		/// creez totul de la zero
		/// un nou pachet ether header
		struct ether_header *eth_hdrNou = malloc(sizeof(struct ether_header));
		eth_hdrNou->ether_type = ntohs(arpValue);
		uint8_t macMeu[6];
		get_interface_mac(interface, macMeu);
		memcpy(eth_hdrNou->ether_shost, macMeu, 6);
		memcpy(eth_hdrNou->ether_dhost, arp_header->sha, 6);

		/// un nou camp arp header
		/// op e 2 pentru ca e reply
		struct arp_header *arp_headerNou = calloc(1, sizeof(struct arp_header));
		arp_headerNou->htype = htons(1);
		arp_headerNou->ptype = htons(0x0800);
		arp_headerNou->hlen = 6;
		arp_headerNou->plen = 4;
		arp_headerNou->op = htons(2);

		/// actualizez dest,sursele
		char *ipMeuChar = get_interface_ip(interface);
		uint32_t ipMeu = inet_addr(ipMeuChar);
		memcpy(arp_headerNou->sha, macMeu, 6);
		arp_headerNou->spa = ipMeu;

		memcpy(arp_headerNou->tha, arp_header->sha, 6);
		arp_headerNou->tpa = arp_header->spa;

		memcpy(packet, eth_hdrNou, sizeof(struct ether_header));
		memcpy(packet + sizeof(struct ether_header), arp_headerNou, sizeof(struct arp_header));

		/// trimit pe aceasi interfata
		send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct arp_header));
	}
}
void generateArpRequest(struct route_table_entry *next, int interface)
{
	char packet[MAX_PACKET_LEN];
	/// creez un nou ether header
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	eth_hdr->ether_type = htons(arpValue);

	uint8_t macMeu[6];
	get_interface_mac(next->interface, macMeu);
	/// setez sursa si destinatia
	memcpy(eth_hdr->ether_shost, macMeu, 6);
	memcpy(eth_hdr->ether_dhost, broadcast, 6);
	/// acum crearea pachetului ARP
	struct arp_header *arp_header = malloc(sizeof(struct arp_header));
	arp_header->htype = htons(1);
	arp_header->ptype = htons(0x0800);
	arp_header->hlen = 6;
	arp_header->plen = 4;
	arp_header->op = htons(1);
	/// op code ul 1 pentru ca e request
	char *ipMeuChar = get_interface_ip(next->interface);
	uint32_t ipMeu = inet_addr(ipMeuChar);
	memcpy(arp_header->sha, macMeu, 6);
	arp_header->spa = ipMeu;
	memset(arp_header->tha, 0, 6);
	arp_header->tpa = next->next_hop;
	/// adaug in packet headerele
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), arp_header, sizeof(struct arp_header));

	/// trimit pachetul
	send_to_link(next->interface, packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}
void routerReply(char *packet, char *buf, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	///creez un nou ether_header
	struct ether_header *eth_hdrIcmp = malloc(sizeof(struct ether_header));
	memcpy(eth_hdrIcmp->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdrIcmp->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_shost));
	eth_hdrIcmp->ether_type = htons(ipV4Value);
	///creez un nou ip header
	struct iphdr *iphdrIcmp = malloc(sizeof(struct iphdr));
	iphdrIcmp->check = 0;
	iphdrIcmp->version = 4;
	iphdrIcmp->ihl = 5;
	iphdrIcmp->tos = 0;

	iphdrIcmp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr)); /// pt router reply
	iphdrIcmp->id = htons(1);
	iphdrIcmp->frag_off = 0;
	iphdrIcmp->ttl = 64;
	iphdrIcmp->protocol = 1;

	iphdrIcmp->saddr = (uint32_t)inet_addr(get_interface_ip(interface));
	iphdrIcmp->daddr = ip_hdr->saddr;

	iphdrIcmp->check = htons(checksum((uint16_t *)iphdrIcmp, sizeof(struct iphdr)));
	memcpy(packet, eth_hdrIcmp, sizeof(struct ether_header));
	///modific vechiul icmphdr primit de la ping router
	struct icmphdr *icmphdrVechi = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmphdrVechi->code = 0;
	icmphdrVechi->type = 0;

	icmphdrVechi->checksum = 0;
	icmphdrVechi->checksum = htons(checksum((uint16_t *)icmphdrVechi, sizeof(struct icmphdr)));
	///pun iphdr nou si icmphdr ul vechi modificat
	memcpy(packet + sizeof(struct ether_header), iphdrIcmp, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmphdrVechi, sizeof(struct icmphdr));
}
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	sizeOfRtable = read_rtable(argv[1], rtable);

	for (int i = 0; i < 6; i++)
	{
		broadcast[i] = 0xFF;
	}
	/// creez coada de asteptare pentru pachetele fara corespondenta in ARP table
	coada = queue_create();
	/// sortez tabela de rutare pentru cautarea binara
	sortareRoutingTable(rtable, sizeOfRtable);

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		///daca e pachet de tip ARP am un handler
		if (eth_hdr->ether_type == ntohs(arpValue))
		{
			processArp(eth_hdr, interface, len);
			continue;
		}
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint16_t checksumPrimit = ntohs(ip_hdr->check);
		ip_hdr->check = 0;

		uint16_t checksumValue = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if (checksumValue != checksumPrimit)
		{
			printf("checksum prost\n");
			continue;
		}

		uint8_t mac_interface[6];

		get_interface_mac(interface, mac_interface);

		char ipDaddrString[16];
		uint32_t ipDaddrCopie = ip_hdr->daddr;

		inet_ntop(2, &ipDaddrCopie, ipDaddrString, sizeof(ipDaddrString));
		///asta e cazul cu router reply
		if (strcmp(get_interface_ip(interface), ipDaddrString) == 0)
		{ // type 0 code 0
			char packet[MAX_PACKET_LEN];

			routerReply(packet, buf, interface);

			send_to_link(interface, packet, sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
			continue;
		}

		if (areDifferentMacAddresses(eth_hdr->ether_dhost, broadcast) == 0)
		{
			printf("e pe broadcast\n");
		}
		/// daca nu e ARP sau IPV4 ii dau drop
		if ((ntohs(eth_hdr->ether_type) != arpValue) && (ntohs(eth_hdr->ether_type) != ipV4Value))
		{
			printf("Pachet de tip neacceptat!\n");
			continue;
		}

		if (ip_hdr->ttl <= 1)
		{
			// type 11 cod 0
			char packet[MAX_PACKET_LEN];

			int dim = generareICMPTtlUnreacheable(packet, buf, 0, 11, interface);

			send_to_link(interface, packet, dim);

			printf("Nu am gasit calea urmatoare!\n");
			continue;
		}
		else
			ip_hdr->ttl--;

		/// caut in tabela de rutare next hop

		// find next hop
		struct route_table_entry *next = get_best_route_Binary_Search(ip_hdr->daddr, sizeOfRtable, rtable);
		/// In caz ca nu gaseste nmc aruncat si continuarea cu ICMP
		if (next == NULL)
		{
			// type 3 code 0
			char packet[MAX_PACKET_LEN];

			int dim = generareICMPTtlUnreacheable(packet, buf, 0, 3, interface);
			send_to_link(interface, packet, dim);

			printf("Nu am gasit calea urmatoare!\n");
			continue;
		}

		// recalculez checksum pentru ca s a schimbat TTL
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		/// adresa sursa va fi adresa interfetei routerului, iar adresa destinatie va fi adresa MAC a urmatorului hop
		uint8_t macSend[6];
		get_interface_mac(next->interface, macSend);
		memcpy(eth_hdr->ether_shost, mac_interface, sizeof(mac_interface));

		struct arp_entry *nextHop = NULL;
		nextHop = get_Arp_Entry_fromArpTable(arp_table, arptTableLen, ip_hdr->daddr);
		/// daca nu am corespondenta in tabela ARP il adaug in coada si generez un ARP request
		if (nextHop == NULL)
		{
			struct pachet *packet = malloc(sizeof(struct pachet));
			memcpy(packet->buf, buf, len);
			packet->len = len;
			/// am nevoie si de len pentru trimitere
			/// de aceea am creat o structura pe care o salvez in coada
			queue_enq(coada, (void *)packet);

			generateArpRequest(next, interface);
			continue;
		}
		/// daca nu am avut niciun caz special se trimite pachetul mai departe
		memcpy(eth_hdr->ether_dhost, nextHop->mac, sizeof(nextHop->mac));

		send_to_link(next->interface, buf, len);
	}
	free(rtable);
	free(arp_table);
}
