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
#include <list>
#include <string>
#include <functional>
#include <cstdlib>
#include <ctime>

#include "p2pServer.hpp"

static Node g_selfNode;
static Node g_otherNode;
static char *g_otherIP;
static int g_otherPort;

int p2pNode(int argc, char **argv)
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

	char recvbuff[128] = { 0 };
	char sendbuff[128] = { 0 };
	sprintf(sendbuff, "This is a message sent from %s:%d to %s:%d.",
		g_selfNode.recvIp, g_selfNode.recvPort, g_otherNode.queryIp, g_otherNode.queryPort);

	while (1)
	{
		memset(&recvAddr, 0, sizeof(recvAddr));

		if (sendto(sock, sendbuff, strlen(sendbuff) + 1, 0, (struct sockaddr*)&otherAddr, sizeof(otherAddr)) < 0)
		{
			perror("sendto");
			close(sock);
			exit(4);
		}

		if (recvfrom(sock, recvbuff, sizeof(recvbuff), 0, (struct sockaddr*)&recvAddr, &recvLen) < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			perror("recvfrom");
			close(sock);
			exit(2);
		}

		std::cout << recvbuff << std::endl;
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