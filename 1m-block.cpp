#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unordered_set>
#include <string>
#include <fstream>

#pragma pack(push, 1)
struct IpHdr {
	u_int8_t  ip_header_len:4, ver:4;
	u_int8_t  tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t  ttl;
	u_int8_t  protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct TcpHdr {
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;
	u_int32_t ack_seq;
	u_int8_t  off_res;
	u_int8_t  flags;
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
};
#pragma pack(pop)

std::unordered_set<std::string> site_list;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	     struct nfq_data *nfa, void *data)
{
	unsigned char *packet;
	int len = nfq_get_payload(nfa, &packet);

	struct nfqnl_msg_packet_hdr *pkt_info = nfq_get_msg_packet_hdr(nfa);
	if (pkt_info == NULL)
		return NF_ACCEPT;

	u_int32_t id = ntohl(pkt_info->packet_id);

	if (len < 20)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	struct IpHdr *ip = (struct IpHdr *)packet;

	if (ip->protocol != 6)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	int ip_len = ip->ip_header_len * 4;

	if (ip_len < 20 || len < ip_len + 20)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	struct TcpHdr *tcp = (struct TcpHdr *)(packet + ip_len);

	if (ntohs(tcp->dport) != 80)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	int tcp_len = ((tcp->off_res >> 4) & 0x0f) * 4;

	if (tcp_len < 20 || len < ip_len + tcp_len)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	char *http = (char *)tcp + tcp_len;
	int http_len = len - ip_len - tcp_len;

	if (http_len <= 0)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	char *p = NULL;

	for (int i = 0; i <= http_len - 5; i++) {
		if (memcmp(http + i, "Host:", 5) == 0) {
			p = http + i + 5;
			break;
		}
	}

	if (p != NULL) {
		while (p < http + http_len && *p == ' ')
			p++;

		char host[256] = {0};
		int j = 0;

		while (j < 255 &&
		      p + j < http + http_len &&
		      p[j] != '\r' &&
		      p[j] != '\n' &&
		      p[j] != '\0') {
			host[j] = p[j];
			j++;
		}

		if (site_list.count(host))
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	site_list.reserve(800000);

	std::ifstream f(argv[1]);
	std::string line;

	while (std::getline(f, line)) {
		size_t pos = line.find(',');
		if (pos == std::string::npos)
			continue;

		site_list.emplace(line.substr(pos + 1));
	}

	system("iptables -F");
	system("iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT  -p tcp --sport 80 -j NFQUEUE --queue-num 0");

	struct nfq_handle *h = nfq_open();

	nfq_unbind_pf(h, AF_INET);
	nfq_bind_pf(h, AF_INET);

	struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);

	nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

	int fd = nfq_fd(h);
	char buf[65536];

	while (1) {
		int rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0)
			nfq_handle_packet(h, buf, rv);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);

	system("iptables -F");

	return 0;
}
