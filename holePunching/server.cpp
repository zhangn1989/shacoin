#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <list>
#include <ostream>
#include <algorithm>

#include "p2pServer.hpp"

static std::list<Node> g_lstNode;

static Node &GetQualityNode(std::list<Node> &lstNode, Node &node)
{
	std::list<Node>::iterator it, next;
	for (it = lstNode.begin(); it != lstNode.end(); ++it)
	{
		if(*it == node)
			continue;

		return *it;
	}

	return node;
}

int main(int argc, char **argv)
{
	NodeInfo nodeInfo;
	const unsigned long long nodeSize = sizeof(NodeInfo);
	memset(&nodeInfo, 0, nodeSize);

	char client_ip[16] = { 0 };

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		exit(1);
	}

	int val = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
	{
		perror("setsockopt");
	}

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(SERVERPORT);
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0)
	{
		perror("bind");
		exit(2);
	}

	struct sockaddr_in client;
	socklen_t len = sizeof(client);
	while (1)
	{
		//¶ÁÈ¡Êý¾Ý
		memset(&nodeInfo, 0, nodeSize);
		int r = recvfrom(sock, &nodeInfo, nodeSize, 0, (struct sockaddr*)&client, &len);
		if (r < 0)
		{
			perror("recvfrom");
			exit(3);
		}

		memset(client_ip, 0, sizeof(client_ip));
		inet_ntop(AF_INET, &client.sin_addr, client_ip, sizeof(client_ip));

		switch (nodeInfo.cmd)
		{
		case cmd_register:
			nodeInfo.node.count = 0;
			strcpy(nodeInfo.node.queryIp, client_ip);
			nodeInfo.node.queryPort = ntohs(client.sin_port);
			printf("query:%s:%d\n", nodeInfo.node.queryIp, nodeInfo.node.queryPort);
			printf("recv:%s:%d\n", nodeInfo.node.recvIp, nodeInfo.node.recvPort);
			if (g_lstNode.end() == std::find(g_lstNode.begin(), g_lstNode.end(), nodeInfo.node))
				g_lstNode.push_back(nodeInfo.node);
			if (sendto(sock, &nodeInfo, nodeSize, 0, (struct sockaddr*)&client, len) < 0)
			{
				perror("sendto");
				exit(4);
			}
			break;
		case cmd_unregister:
			g_lstNode.remove(nodeInfo.node);
			break;
		case cmd_getnode:
			if (g_lstNode.size() > 1)
			{
				Node recvNode = nodeInfo.node;
				memset(&nodeInfo, 0, nodeSize);
				nodeInfo.cmd = cmd_getnode;
				nodeInfo.node = GetQualityNode(g_lstNode, recvNode);
				++nodeInfo.node.count;
				if (sendto(sock, &nodeInfo, nodeSize, 0, (struct sockaddr*)&client, len) < 0)
				{
					perror("sendto");
					exit(4);
				}
			}
			break;
		default:
			break;
		}
	}
	return 0;
}
