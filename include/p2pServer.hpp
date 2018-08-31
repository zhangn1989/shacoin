#ifndef __P2PSERVER_H
#define __P2PSERVER_H

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/ioctl.h>
#include <net/if.h>

namespace ShaCoin
{
#define ALITEST	0

#if ALITEST
#define SERVERIP	"47.94.162.207"
#define LOCALPORT	10000
	//#define IF_NAME "eth0"
#else //1
#define SERVERIP	"192.168.180.133"
#define LOCALPORT	20000
	//#define IF_NAME "ens33"
#endif //1

#define SERVERPORT	9527

	typedef enum
	{
		cmd_register = 0x1000,
		cmd_unregister,
		cmd_getnode,
		cmd_max
	} Command;

	typedef struct st_node
	{
		int count;
		char queryIp[16];
		int queryPort;
		char recvIp[16];
		int recvPort;

		bool operator == (const struct st_node & value) const
		{
			return
				this->count == value.count &&
				this->queryPort == value.queryPort &&
				this->recvPort == value.recvPort &&
				!strcmp(this->queryIp, value.queryIp) &&
				!strcmp(this->recvIp, value.recvIp);
		}
	} __attribute__((packed))
		Node;

	typedef struct st_nodeinfo
	{
		Command cmd;
		Node node;
	} __attribute__((packed))
		NodeInfo;
}
#endif // __P2PSERVER_H