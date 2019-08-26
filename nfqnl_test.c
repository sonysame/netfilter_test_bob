#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>



unsigned char method[6][10]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
unsigned char host_identifier[10]="Host: ";
unsigned char *host_name;
unsigned char *host;

int flag;

void netfilter(char * p, int len){
	int i,j;
	struct ip * ip_ptr=(struct ip *)p;
	if((ip_ptr->ip_v==4)&&(ip_ptr->ip_p==IPPROTO_TCP)){
		unsigned int ip_hlen=(ip_ptr->ip_hl)*4;
		unsigned int ip_tlen=ip_ptr->ip_len;
		struct tcphdr * tcp_ptr=(struct tcphdr *)(p+ip_hlen);
		unsigned int tcp_hlen=(tcp_ptr->th_off)*4;
		unsigned int data_len=(ntohs(ip_tlen)-(ip_hlen+tcp_hlen));
		unsigned char * data=(unsigned char *)(p+ip_hlen+tcp_hlen);
		for(i=0;i<6;i++){
			if(!strncmp(data, method[i],strlen(method[i])))break;
		}
		if(i!=6){
			for(i=0;i<data_len-strlen(host)-strlen(host_identifier);i++){
				if(!strncmp(data+i,host_identifier,strlen(host_identifier))){
					for(j=i+strlen(host_identifier);j<=i+strlen(host_identifier)+strlen(host)+30;j++){
						if(*(data+j)=='\xd'){
							strncpy(host_name, data+i+strlen(host_identifier),j-(i+strlen(host_identifier)));
							printf("Host name is: %s\n",host_name);	
							if(!(strcmp(host_name, host))){
								memset(host_name, '\x0',strlen(host_name));
								flag=1;
								return;
							}
							memset(host_name, '\x0',strlen(host_name));
							return;
						}
					}
				}
			}
		}
	}
	return;
}





/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)id = ntohl(ph->packet_id);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		flag=0;
		netfilter(data, ret);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	if(flag)return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	host=argv[1];
	host_name=(u_char*)malloc(sizeof(u_char)*strlen(host)+30);
	printf("\n***blocking target host is %s***\n\n",host);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
