/* iptables module for the Linux User Service Policy Engine (USPE)
 *
 * (C) 2011,2012 by Artjom Nikushkin <arni@arni.lv>
 *
*/
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "uspe_plugin.h"
#include "uspe_tproxy.h"


extern int uspe_action_pack(char *argv[], int argc, u_int8_t *data, size_t data_len);
int uspe_action_pack(char *argv[], int argc, u_int8_t *data, size_t data_len){
	struct my_tproxy_data *my_data;

	if(argc != 4) return -EFAULT;
	my_data = (struct my_tproxy_data *)data;
	my_data->port = htons((unsigned) atoi(argv[2]));
	if(!my_data->port && (argv[2][0] != '0')) return -EFAULT;

	my_data->fwmark= (unsigned) atoi(argv[3]);
	if(!my_data->fwmark && (argv[3][0] != '0')) return -EFAULT;

	if(inet_pton(AF_INET, argv[1], &my_data->ip) <= 0) return -EFAULT;

	return sizeof(*my_data);
}

extern int uspe_action_unpack(char *buffer, size_t buflen, u_int8_t *data, size_t data_len);
int uspe_action_unpack(char *buffer, size_t buflen, u_int8_t *data, size_t data_len){
	struct my_tproxy_data *my_data;
	char buf[30];

	if(data_len != sizeof(*my_data)) {
		return -EFAULT;
	}
	my_data = (struct my_tproxy_data *)data;
	inet_ntop(AF_INET, &my_data->ip, buf, 30);
	snprintf(buffer, buflen, "TPROXY %s %u %u", buf,  ntohs(my_data->port), my_data->fwmark);

	return 0;
}

extern int uspe_action_help();
int uspe_action_help(){
	printf("... TPROXY <ip> <port> <fw_mark>\n");
	return 0;
}
 
