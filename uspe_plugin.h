/*
	USPE plugin architecture module
*/
#ifndef _IP_USPE_PLUGIN_H
#define _IP_USPE_PLUGIN_H

#define USPE_PLUGIN_MAX_DATA	32
#define USPE_PLUGIN_NAME_LEN	32

typedef int (*uspe_plugin_pack_t)(char *argv[], int argc, u_int8_t *data, int max_data_len);
typedef int (*uspe_plugin_unpack_t)(char *buffer, size_t size, u_int8_t *data, int data_len);
typedef int (*uspe_plugin_help_t)(void);

struct profile_plugin_action {
	u_int32_t		id;
	char			name[USPE_PLUGIN_NAME_LEN];
	u_int8_t		data[USPE_PLUGIN_MAX_DATA];
	u_int16_t		data_len;
};
struct profile_plugin_match {
	u_int32_t		id;
	char			name[USPE_PLUGIN_NAME_LEN];
	u_int8_t		data[USPE_PLUGIN_MAX_DATA];
	u_int16_t		data_len;
};




#ifdef __KERNEL__
struct uspe_plugin_args {
	struct sk_buff 		*skb;
	u_int8_t		*data;
	int			data_len;
};

#define USPE_PLUGIN_MATCH	1
#define USPE_PLUGIN_NO_MATCH	0
#define USPE_PLUGIN_ERROR	(-1)
typedef int (*uspe_match_function_t)(struct uspe_plugin_args *pa);
typedef int (*uspe_match_check_function_t)(const void *data, int len);



struct uspe_plugin_descriptor {
	char			name[USPE_PLUGIN_NAME_LEN];

	uspe_match_function_t	func;
	uspe_match_check_function_t	check_func;
};

// Profile Plugin API
extern int uspe_plugin_load_match(struct uspe_plugin_descriptor *p);
extern int uspe_plugin_load_action(struct uspe_plugin_descriptor *p);
extern int uspe_plugin_unload_match(struct uspe_plugin_descriptor *p);
extern int uspe_plugin_unload_action(struct uspe_plugin_descriptor *p);

struct uspe_plugin_match {
	struct list_head 	list;
	u_int32_t		id;

	struct uspe_plugin_descriptor data;
};

/* NAT protocol plugins */
struct uspe_nat4_match_args {
	u_int32_t		public_ip;
	u_int32_t		private_ip;
	u_int16_t		new_port;
	u_int16_t		port;
};

typedef int (*uspe_snat4_translate_t)(struct sk_buff *skb, struct uspe_nat4_match_args *na);
struct snat4_proto_handler {
	uspe_snat4_translate_t	check_up;
	uspe_snat4_translate_t	check_down;
	uspe_snat4_translate_t	translate_up;
	uspe_snat4_translate_t	translate_down;
};

extern int uspe_snat4_register_proto(u_int8_t proto, struct snat4_proto_handler *h);
extern int uspe_snat4_unregister_proto(u_int8_t proto);


#else /* __KERNEL__ */


#endif
#endif
