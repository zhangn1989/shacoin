#ifndef __P2PSERVER_H
#define __P2PSERVER_H

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/ioctl.h>
#include <net/if.h>

namespace ShaCoin
{
#define ALITEST	1

#if ALITEST
#define SERVERIP	"47.94.162.207"
#define LOCALPORT	10000
	//#define IF_NAME "eth0"
#else //1
#define SERVERIP	"192.168.180.130"
#define LOCALPORT	20000
	//#define IF_NAME "ens33"
#endif //1

#define SERVERPORT	9527
#define MAX_UDP_SIZE	65507
#define MAX_P2P_SIZE	MAX_UDP_SIZE - sizeof(int) *3 - sizeof(p2pCommand) - sizeof(size_t)

	typedef enum
	{
		cmd_register = 0,
		cmd_unregister,
		cmd_getnode,
		cmd_max
	} Command;

	typedef enum
	{
		p2p_transaction = 0,
		p2p_bookkeeping,
		p2p_result,
		p2p_max
	} p2pCommand;

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

	typedef struct st_p2pMessage
	{
		int group;
		int index;
		int total;
		p2pCommand cmd;
		size_t length;
		char mess[MAX_P2P_SIZE];
	} __attribute__((packed))
		p2pMessage;

	typedef struct st_p2pResult
	{
		int group;
		int index;
	} __attribute__((packed))
		p2pResult;
}
#endif // __P2PSERVER_H