#ifndef _IPV4_HUNTER_HEADER
#define _IPV4_HUNTER_HEADER

#define IP_MAGIC	'N'

#define MAX_IP_NUM	12
#define MAX_IP_LEN	20

#define MAX_IP_QUERY_NUM	50

struct ip_add_param{
	unsigned int num;
	char *ip_strs[MAX_IP_NUM];
};

struct ip_del_param{
	unsigned int num;
	char *ip_strs[MAX_IP_NUM];
};


struct ip_query_param{
	unsigned int num;
	char *ip_strs[MAX_IP_QUERY_NUM];
};

typedef union ip_param {
	struct ip_add_param add_param;
	struct ip_del_param del_param;
	struct ip_query_param query_param;
}ip_param_t;

#define IP_ADD		_IOWR(IP_MAGIC, 0, \
				      struct ip_add_param)

#define IP_DEL		_IOWR(IP_MAGIC, 1, \
				      struct ip_del_param)

#define IP_QUERY		_IOWR(IP_MAGIC, 2, \
				      struct ip_query_param)
#endif
