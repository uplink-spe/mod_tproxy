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
#include "uspe_plugin.h"
#include "uspe_tproxy.h"


extern int uspe_match_pack(char *argv[], int argc, u_int8_t *data, size_t data_len);
int uspe_match_pack(char *argv[], int argc, u_int8_t *data, size_t data_len){
	return 0;
}

extern int uspe_match_unpack(char *buffer, size_t buflen, u_int8_t *data, size_t data_len);
int uspe_match_unpack(char *buffer, size_t buflen, u_int8_t *data, size_t data_len){

	snprintf(buffer, buflen, "tproxy");
	return 0;
}

extern int uspe_match_help();
int uspe_match_help(){
	printf("tproxy	- match if packet belongs to a ongoing connection");
	return 0;
}
 
