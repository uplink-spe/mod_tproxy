#ifndef _IP_USPE_TPROXY_H
#define _IP_USPE_TPROXY_H

#include <linux/types.h>

struct my_tproxy_data {
	__be32		ip;
	__be32		fwmark;
	__be16		port;
}  __attribute__((packed));



#endif
