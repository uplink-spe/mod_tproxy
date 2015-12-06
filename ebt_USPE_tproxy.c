/* iptables module for the Linux User Service Policy Engine (USPE)
 *
 * (C) 2011 by Artjom Nikushkin <arni@arni.lv>
 *
 * Code is mostly copied from 
 *	linux/net/netfilter/xt_TPROXY.c
 * 	linux/net/netfilter/xt_socket.c
 *
 * 	only TCP sockets are supported here
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/sock.h>
#include "uspe_plugin.h"
#include "uspe_tproxy.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Uplink SIA <arni@uplink.lv>");
MODULE_DESCRIPTION("Xtables: USPE Tproxy module");
MODULE_VERSION("1.0");


int tproxy_mt(struct uspe_plugin_args *pa);
int tproxy_mt_ck(const void *data, int len);
int tproxy_act(struct uspe_plugin_args *pa);
int tproxy_act_ck(const void *data, int len);

static int uspe_tproxy_match(struct sk_buff *skb);
static int uspe_tproxy_action(struct sk_buff *skb, __be32 ip, __be16 port, __u32 fwmark);
static bool uspe_sk_is_transparent(struct sock *sk);

static struct uspe_plugin_descriptor match, action;

static int __init init(void){
	memset(&match, 0, sizeof(match));
	memset(&action, 0, sizeof(action));

	// Setup match 	
	sprintf(match.name, "tproxy");
	match.func = tproxy_mt;
	match.check_func = tproxy_mt_ck;
	if(uspe_plugin_load_match(&match) != 0) return -EFAULT;

	// Setup action
	sprintf(action.name, "TPROXY");
	action.func = tproxy_act;
	action.check_func = tproxy_act_ck;
	if(uspe_plugin_load_action(&action) != 0){
		uspe_plugin_unload_match(&match);
		return -EFAULT;
	}

	return 0;
}

static void __exit fini(void)
{
	uspe_plugin_unload_match(&match);
	uspe_plugin_unload_action(&action);
}

/*
*	Cacllbacks
*
*/

int tproxy_mt(struct uspe_plugin_args *pa){
	if(tproxy_mt_ck(pa->data, pa->data_len) != 0) return -EFAULT;

	return uspe_tproxy_match(pa->skb);
}

int tproxy_mt_ck(const void *data, int len){
	return 0;
}

int tproxy_act(struct uspe_plugin_args *pa){
	const struct my_tproxy_data *args;

	if(tproxy_act_ck(pa->data, pa->data_len) != 0) return -EFAULT;

	args = (struct my_tproxy_data*) pa->data;

	return uspe_tproxy_action(pa->skb, args->ip, args->port, args->fwmark);
}

int tproxy_act_ck(const void *data, int len){
	if(len == sizeof(struct my_tproxy_data)) return 0;
	return -EFAULT;
}


/*
*	Implementation of interal functions :
*
*
*/


 
static int uspe_tproxy_action(struct sk_buff *skb, __be32 ip, __be16 port, __u32 fwmark){
	const struct iphdr *iph;
	const struct tcphdr *tcph;
	struct sock *sk;
	int ret = -ENOENT;

 	iph = ip_hdr(skb);
	if (!iph || (iph->protocol != IPPROTO_TCP)) return -EFAULT;

	tcph = tcp_hdr(skb);
	if (!tcph) return -EFAULT;

	/* check if there's an ongoing connection on the packet
	* addresses, this happens if the redirect already happened
	* and the current packet belongs to an already established
	* connection */
	sk = inet_lookup_established(dev_net(skb->dev), &tcp_hashinfo,
		iph->saddr, tcph->source, iph->daddr, tcph->dest, skb->skb_iif);
	if(!sk){
		/* no, there's no established connection, check if
		* there's a listener on the redirected addr/port */
		sk = inet_lookup_listener(dev_net(skb->dev), &tcp_hashinfo, 
			iph->saddr, tcph->source, ip, port, skb->skb_iif);
		//pr_info("tpr: listener is %p", sk);
	}

	if(!sk) return -ENOENT;

	if (sk->sk_state == TCP_TIME_WAIT){
		// reopening a TIME_WAIT connection needs special handling
		if (tcph->syn && !tcph->rst && !tcph->ack && !tcph->fin) {
			struct sock *sk2;
			//SYN to a TIME_WAIT socket, we'd rather redirect it
			//   to a listener socket if there's one 
			sk2 = inet_lookup_listener(dev_net(skb->dev), &tcp_hashinfo,
				iph->saddr, tcph->source, ip, port, skb->skb_iif);

			if (sk2) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
				inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
#else
				inet_twsk_deschedule(inet_twsk(sk));
#endif
				inet_twsk_put(inet_twsk(sk));	// release original sk
				sk = sk2;
			}
			//pr_info("tpr: matched TW sock, %p", sk2);
		}
	} 

	/* NOTE: assign_sock consumes our sk reference */
	if (uspe_sk_is_transparent(sk)) {
		skb->mark |= fwmark;

		skb_orphan(skb);
		skb->sk = sk;
		skb->destructor = sock_edemux;

		//pr_info("tpr: set sock");
		ret =  USPE_PLUGIN_MATCH;
	}

	// need to release socket anyway
	if (sk->sk_state != TCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
	} else {
		sock_gen_put(sk);
	}

	return ret;
}

static int uspe_tproxy_match(struct sk_buff *skb){
	struct sock *sk;
	struct tcphdr *tcph;
	struct iphdr *iph;
	int transparent;

	iph = ip_hdr(skb);
	if (!iph || (iph->protocol != IPPROTO_TCP)) return 0;

	tcph = tcp_hdr(skb);
	if (!tcph) return 0;

	sk = __inet_lookup(dev_net(skb->dev), &tcp_hashinfo, iph->saddr, tcph->source, iph->daddr, tcph->dest, skb->skb_iif);
	if (!sk) return 0;

	// ignore wildcard
	if ((sk->sk_state != TCP_TIME_WAIT) && (inet_sk(sk)->inet_rcv_saddr == 0)) return 0;

	//Ignore non-transparent sockets
	transparent = (
		(sk->sk_state != TCP_TIME_WAIT && inet_sk(sk)->transparent) ||
		(sk->sk_state == TCP_TIME_WAIT && inet_twsk(sk)->tw_transparent)
	);

	if (sk->sk_state != TCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
	} else {
		sock_gen_put(sk);
	}

	return transparent;
}

static bool uspe_sk_is_transparent(struct sock *sk){
	if(!sk) return false;

	switch (sk->sk_state) {
	case TCP_TIME_WAIT:
 		if (inet_twsk(sk)->tw_transparent) return true;
 		break;
 	case TCP_NEW_SYN_RECV:
 		if (inet_rsk(inet_reqsk(sk))->no_srccheck) return true;
		break;
 	default:
 		if (inet_sk(sk)->transparent) return true;
 	}
 	return false;
}
 

module_init(init);
module_exit(fini);
