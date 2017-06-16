/*
 *	Author: Yonggang Guo <hero.gariker@gmail.com>
 *	Date: 2017.06.16
 */

#include <stdio.h>
#include <sys/types.h>  
#include <sys/stat.h>    
#include <fcntl.h>
#include <errno.h>
#include "cmd.h"
	
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
enum {
	HELP = 0,
	ADD_ONE_NODE,
	DEL_ONE_NODE,
	ADD_NODES,
	DEL_NODES,
	CLEAR_NODES,
	QUERY,
};

#define MAX_FILE_LEN	256

static int work_mode = -1;
static char file_path[MAX_FILE_LEN];
static char ip_str[MAX_IP_LEN];

static char query_strs[MAX_IP_QUERY_NUM][MAX_IP_LEN];

static void help() 
{
	printf(GREEN "Usage: inet_filter [option] [pattern [pattern]]\n");
	printf("\t\texample: inet_filter -a 180.149.131.248\n\n");
	printf("\t-h, --help\t\tthis message\n");
	printf("\t-a, --add\t\tadd ip node\n");
	printf("\t-r, --addfile\t\tadd ip node from file\n");
	printf("\t-d, --delete\t\tdelete ip node\n");
	printf("\t-v, --delfile\t\tdelete ip node from file\n");
	printf("\t-c, --clear\t\tclear ip node\n");
	printf("\t-q, --query\t\tquery ip nodes\n");
	printf(WHITE);
}

static inline int open_ip_filter()
{
	int fd;

	fd = open("/proc/ip_filter", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	return fd;
}

static inline int ip_filter_ioctl(int fd, int cmd, unsigned long arg)
{
	int ret;
	
	ret = ioctl(fd, cmd, arg);
	return ret;
}

static inline void close_ip_filter(int fd)
{
	close(fd);
}



int select_work_mode(int argc, char **argv)
{
	int i;
	char *str;
	unsigned long count;
	
	work_mode = HELP;
	memset(file_path, 0x0, sizeof file_path);
	memset(ip_str, 0x0, sizeof ip_str);
	if (argc <= 1 || argc > 3)
		return work_mode;
	
	if (argc == 2) {
		if (strcmp(argv[1], "-c") == 0)
			work_mode = CLEAR_NODES;

		if (strcmp(argv[1], "-q") == 0)
			work_mode = QUERY;
				
		return work_mode;
	}
	
	count = strlen(argv[2]);
	if (strcmp(argv[1], "-a") == 0) {
		work_mode = ADD_ONE_NODE;
		count = count > (MAX_IP_LEN - 1) ? (MAX_IP_LEN - 1) : count;
		memcpy(ip_str, argv[2], count);
	} else if (strcmp(argv[1], "-d") == 0) {
		work_mode = DEL_ONE_NODE;
		count = count > (MAX_IP_LEN - 1) ? (MAX_IP_LEN -1) : count;
		memcpy(ip_str, argv[2], count);
	} else if (strcmp(argv[1], "-r") == 0) {
		work_mode = ADD_NODES;
		count = count > (MAX_FILE_LEN - 1) ? (MAX_FILE_LEN - 1) : count;
		memcpy(file_path, argv[2], count);
	} else if (strcmp(argv[1], "-v") == 0) {
		work_mode = DEL_NODES;
		count = count > (MAX_FILE_LEN - 1) ? (MAX_FILE_LEN - 1) : count;
                memcpy(file_path, argv[2], count);
	}

	return work_mode;
}


void printf_query_result(struct ip_query_param *param)
{
	int i;
	
	printf("Block IP List[%d]:\n", param->num);
	for (i = 0; i < param->num; i++)
		printf("[%02d][%s]\n", i + 1, param->ip_strs[i]); 

}

int main(int argc, char **argv)
{
	int ret, i;
	int fd;
	ip_param_t param;
	
	struct ip_add_param *add_param;
	struct ip_del_param *del_param;
	struct ip_query_param *query_param;
	
	printf(GREEN);      
	select_work_mode(argc, argv);
	fd = open_ip_filter();
	if (fd < 0) {
		goto failed;		
	}
	
	switch(work_mode) {
	case ADD_ONE_NODE:
		add_param = &param.add_param;
		add_param->num = 1;
		add_param->ip_strs[0] = ip_str;
		ret = ip_filter_ioctl(fd, IP_ADD, (unsigned long)&param);
		if (ret < 0) 
			printf("add ip:%s failed\n", ip_str);
		else 
			printf("add ip:%s\n", ip_str);
		break;
	case DEL_ONE_NODE:
		del_param = &param.del_param;
		del_param->num = 1;
		del_param->ip_strs[0] = ip_str;
		ret = ip_filter_ioctl(fd, IP_DEL, (unsigned long)&param);
		if (ret < 0)
			printf("del ip:%s failed\n", ip_str);
		else
			printf("del ip:%s\n", ip_str);
		break;
	case ADD_NODES:
		printf("not support!\n");
		break;
	case DEL_NODES:
		printf("not support!\n");
		break;
	case CLEAR_NODES:
		printf("[clear all ip\n");
		break;
	case QUERY:	
		query_param = &param.query_param;
		query_param->num = MAX_IP_QUERY_NUM -1;
		for (i = 0; i < MAX_IP_QUERY_NUM; i++) 
			query_param->ip_strs[i] = query_strs[i];
		
		ret = ip_filter_ioctl(fd, IP_QUERY, (unsigned long)&param);
		if (ret >= 0)
			printf_query_result(query_param);
		break;
	case HELP:
		help();
		break;
	default:
		fprintf(stderr, "work mode error\n");
		break;
	}
	
	close_ip_filter(fd);
failed:
	printf(WHITE);
	return 0;	
}

