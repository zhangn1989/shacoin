#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#include <iostream>
#include <string>
#include <functional>
#include <cstdlib>
#include <ctime>
#include <map>

#include "p2pNode.hpp"

namespace ShaCoin
{
	P2PNode::P2PNode(const char *if_name)
	{
		m_sock = socket(AF_INET, SOCK_DGRAM, 0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）  
		if (m_sock < 0)
		{
			perror("socket\n");
			return ;
		}

		int val = 1;
		if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
		{
			perror("setsockopt");
		}

		struct timeval tv_out;
		tv_out.tv_sec = 10;//等待10秒
		tv_out.tv_usec = 0;
		if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0)
		{
			perror("setsockopt");
		}

		memset(&m_serverAddr, 0, sizeof(m_serverAddr));
		m_serverAddr.sin_family = AF_INET;
		m_serverAddr.sin_port = htons(SERVERPORT);
		m_serverAddr.sin_addr.s_addr = inet_addr(SERVERIP);
		socklen_t serverLen = sizeof(m_serverAddr);

		memset(&m_localAddr, 0, sizeof(m_localAddr));
		m_localAddr.sin_family = AF_INET;
		m_localAddr.sin_port = htons(LOCALPORT);
		m_localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(m_sock, (struct sockaddr*)&m_localAddr, sizeof(m_localAddr)) < 0)
		{
			perror("bind");
			close(m_sock);
			exit(2);
		}

		
		memset(&m_recvAddr, 0, sizeof(m_recvAddr));
		socklen_t recvLen = sizeof(m_recvAddr);

		NodeInfo sendNode, recvNode;
		memset(&sendNode, 0, sizeof(NodeInfo));
		memset(&recvNode, 0, sizeof(NodeInfo));
		sendNode.cmd = cmd_register;
		sendNode.node.recvPort = LOCALPORT;
		get_local_ip(if_name, sendNode.node.recvIp);

		while (1)
		{
			if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
			{
				perror("sendto");
				close(m_sock);
				exit(4);
			}

			memset(&m_recvAddr, 0, sizeof(m_recvAddr));
			memset(&recvNode, 0, sizeof(NodeInfo));
			if (recvfrom(m_sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				close(m_sock);
				exit(2);
			}

			if (recvNode.cmd != cmd_register)
				continue;

			m_selfNode = recvNode.node;
			break;
		}

		while (1)
		{
			memset(&sendNode, 0, sizeof(NodeInfo));
			memset(&recvNode, 0, sizeof(NodeInfo));
			memset(&m_recvAddr, 0, sizeof(m_recvAddr));

			sendNode.cmd = cmd_getnode;
			sendNode.node = m_selfNode;
			if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
			{
				perror("sendto");
				close(m_sock);
				exit(4);
			}

			if (recvfrom(m_sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				close(m_sock);
				exit(2);
			}

			if (recvNode.cmd != cmd_getnode)
				continue;

			m_otherNode = recvNode.node;
			break;
		}

		//查询到的IP和接收到的IP如果不相同，则是内网环境
		//自己查询到的IP和另一个节点查询到的IP如果相同，则处于同一内网
		//同一内网的节点用内网传输数据，不在同一内网的节点只能用公网传输数据
		if (strcmp(m_selfNode.queryIp, m_selfNode.recvIp) &&
			!strcmp(m_selfNode.queryIp, m_otherNode.queryIp))
		{
			m_otherIP = m_otherNode.recvIp;
			m_otherPort = m_otherNode.recvPort;
		}
		else
		{
			m_otherIP = m_otherNode.queryIp;
			m_otherPort = m_otherNode.queryPort;
		}

		pthread_mutex_init(&m_mutex, NULL);
	}

	P2PNode::~P2PNode()
	{
		NodeInfo sendNode;
		memset(&sendNode, 0, sizeof(NodeInfo));

		socklen_t serverLen = sizeof(m_serverAddr);

		sendNode.cmd = cmd_unregister;
		sendNode.node = m_selfNode;
		if (sendto(m_sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&m_serverAddr, serverLen) < 0)
		{
			perror("sendto");
			close(m_sock);
			exit(4);
		}

		close(m_sock);

		pthread_mutex_destroy(&m_mutex);
	}

	P2PNode* P2PNode::Instance(const char *if_name)
	{
		static P2PNode node(if_name);
		return &node;
	}

	void P2PNode::Listen()
	{
		if (pthread_create(&m_tid, NULL, threadFunc, this) != 0)
		{
			close(m_sock);
			exit(2);
		}
	}

	void *P2PNode::threadFunc(void *arg)
	{
		P2PNode *p = (P2PNode*)arg;
		p->threadHandler();
		return NULL;
	}

	void P2PNode::threadHandler()
	{
		sockaddr_in otherAddr;
		memset(&otherAddr, 0, sizeof(otherAddr));
		otherAddr.sin_family = AF_INET;
		otherAddr.sin_port = htons(m_otherPort);
		otherAddr.sin_addr.s_addr = inet_addr(m_otherIP);

		p2pMessage mess;
		p2pResult result;

		socklen_t recvLen = sizeof(m_recvAddr);

		threadPool<p2pMessage, P2PNode> tp(5);
		tp.setTaskFunc(this, &P2PNode::combinationPackage);
		tp.start();

		while (1)
		{
			memset(&mess, 0, sizeof(p2pMessage));
			memset(&result, 0, sizeof(p2pResult));
			memset(&m_recvAddr, 0, sizeof(m_recvAddr));

			if (recvfrom(m_sock, &mess, sizeof(p2pMessage), 0, (struct sockaddr*)&m_recvAddr, &recvLen) < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;

				perror("recvfrom");
				tp.stop();
				close(m_sock);
				exit(2);
			}

			tp.addTask(mess);

			result.group = mess.group;
			result.index = mess.index;
			if (sendto(m_sock, &result, sizeof(p2pResult) + 1, 0, (struct sockaddr*)&m_recvAddr, sizeof(m_recvAddr)) < 0)
			{
				perror("sendto");
				tp.stop();
				close(m_sock);
				exit(4);
			}
		}
		tp.stop();
	}

	void P2PNode::combinationPackage(p2pMessage &mess)
	{
		Package package;
		int index = mess.index;
		std::list<Package>::iterator it;

		pthread_mutex_lock(&m_mutex);
		for (it = m_lstPackage.begin(); it != m_lstPackage.end(); ++it)
		{
			if (it->group == mess.group)
				break;
		}

		if (it == m_lstPackage.end())
		{
			package.group = mess.group;
			package.total = mess.total;
			package.cmd = mess.cmd;
			package.mapMess.insert(std::pair<int, std::string>(index, std::string(mess.mess, mess.length)));
			m_lstPackage.push_back(package);
		}
		else
		{
			it->mapMess.insert(std::pair<int, std::string>(index, std::string(mess.mess, mess.length)));
			package = *it;
		}
		pthread_mutex_unlock(&m_mutex);

		if (package.total == (int)package.mapMess.size())
		{
			std::string strJson;
			std::map<int, std::string>::iterator mapIt;
			for (mapIt = package.mapMess.begin(); mapIt != package.mapMess.end(); ++mapIt)
			{
				strJson += mapIt->second;
			}

			switch (package.cmd)
			{
			case p2p_transaction:
				break;
			case p2p_bookkeeping:
				break;
			case p2p_result:
				break;
			default:
				break;
			}
		}
	}

	int P2PNode::get_local_ip(const char *ifname, char *ip)
	{
		char *temp = NULL;
		int inet_sock;
		struct ifreq ifr;

		inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		memcpy(ifr.ifr_name, ifname, strlen(ifname));

		if (0 != ioctl(inet_sock, SIOCGIFADDR, &ifr))
		{
			perror("ioctl error");
			return -1;
		}

		temp = inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);
		memcpy(ip, temp, strlen(temp));

		close(inet_sock);

		return 0;
	}
}



#if 0

static Node g_selfNode;
static Node g_otherNode;
static char *g_otherIP;
static int g_otherPort;

int P2PNode(int argc, char **argv)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）  
	if (sock < 0)
	{
		perror("socket\n");
		return 2;
	}

	int val = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
	{
		perror("setsockopt");
	}

	struct timeval tv_out;
	tv_out.tv_sec = 10;//等待10秒
	tv_out.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0)
	{
		perror("setsockopt");
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SERVERPORT);
	serverAddr.sin_addr.s_addr = inet_addr(SERVERIP);
	socklen_t serverLen = sizeof(serverAddr);

	struct sockaddr_in localAddr;
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(LOCALPORT);
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0)
	{
		perror("bind");
		close(sock);
		exit(2);
	}

	sockaddr_in recvAddr;
	memset(&recvAddr, 0, sizeof(recvAddr));
	socklen_t recvLen = sizeof(recvAddr);

	NodeInfo sendNode, recvNode;
	memset(&sendNode, 0, sizeof(NodeInfo));
	memset(&recvNode, 0, sizeof(NodeInfo));
	sendNode.cmd = cmd_register;
	sendNode.node.recvPort = LOCALPORT;
	get_local_ip(argv[1], sendNode.node.recvIp);

	while (1)
	{
		if (sendto(sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&serverAddr, serverLen) < 0)
		{
			perror("sendto");
			close(sock);
			exit(4);
		}

		memset(&recvAddr, 0, sizeof(recvAddr));
		memset(&recvNode, 0, sizeof(NodeInfo));
		if (recvfrom(sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&recvAddr, &recvLen) < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			perror("recvfrom");
			close(sock);
			exit(2);
		}

		if (recvNode.cmd != cmd_register)
			continue;

		g_selfNode = recvNode.node;
		break;
	}

	while (1)
	{
		memset(&sendNode, 0, sizeof(NodeInfo));
		memset(&recvNode, 0, sizeof(NodeInfo));
		memset(&recvAddr, 0, sizeof(recvAddr));

		sendNode.cmd = cmd_getnode;
		sendNode.node = g_selfNode;
		if (sendto(sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&serverAddr, serverLen) < 0)
		{
			perror("sendto");
			close(sock);
			exit(4);
		}

		if (recvfrom(sock, &recvNode, sizeof(NodeInfo), 0, (struct sockaddr*)&recvAddr, &recvLen) < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			perror("recvfrom");
			close(sock);
			exit(2);
		}

		if (recvNode.cmd != cmd_getnode)
			continue;

		g_otherNode = recvNode.node;
		break;
	}

	//查询到的IP和接收到的IP如果不相同，则是内网环境
	//自己查询到的IP和另一个节点查询到的IP如果相同，则处于同一内网
	//同一内网的节点用内网传输数据，不在同一内网的节点只能用公网传输数据
	if (strcmp(g_selfNode.queryIp, g_selfNode.recvIp) &&
		!strcmp(g_selfNode.queryIp, g_otherNode.queryIp))
	{
		g_otherIP = g_otherNode.recvIp;
		g_otherPort = g_otherNode.recvPort;
	}
	else
	{
		g_otherIP = g_otherNode.queryIp;
		g_otherPort = g_otherNode.queryPort;
	}

	sockaddr_in otherAddr;
	memset(&otherAddr, 0, sizeof(otherAddr));
	otherAddr.sin_family = AF_INET;
	otherAddr.sin_port = htons(g_otherPort);
	otherAddr.sin_addr.s_addr = inet_addr(g_otherIP);

	p2pMessage mess;
	memset(&mess, 0, sizeof(p2pMessage));

	while (1)
	{
		memset(&recvAddr, 0, sizeof(recvAddr));

		if (recvfrom(sock, &mess, sizeof(p2pMessage), 0, (struct sockaddr*)&recvAddr, &recvLen) < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			perror("recvfrom");
			close(sock);
			exit(2);
		}

		switch (mess.cmd)
		{
		case p2p_transaction:

			break;
		case p2p_bookkeeping:
			break;
		default:
			break;
		}

// 		if (sendto(sock, sendbuff, strlen(sendbuff) + 1, 0, (struct sockaddr*)&otherAddr, sizeof(otherAddr)) < 0)
// 		{
// 			perror("sendto");
// 			close(sock);
// 			exit(4);
// 		}

//		std::cout << recvbuff << std::endl;
	}

	memset(&sendNode, 0, sizeof(NodeInfo));
	sendNode.cmd = cmd_unregister;
	sendNode.node = g_selfNode;
	if (sendto(sock, &sendNode, sizeof(NodeInfo), 0, (struct sockaddr*)&serverAddr, serverLen) < 0)
	{
		perror("sendto");
		close(sock);
		exit(4);
	}

	close(sock);
}
#endif