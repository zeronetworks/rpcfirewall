#pragma once

#include <rpc.h>

struct RpcStringWrapper
{
	RPC_WSTR* getRpcPtr()
	{
		return (RPC_WSTR*)&str;
	}

	~RpcStringWrapper()
	{
		if (str != nullptr)
		{
			RpcStringFree(getRpcPtr());
		}
	}

	wchar_t* str = nullptr;
};

struct RpcBindingWrapper
{
	~RpcBindingWrapper()
	{
		if (binding != nullptr)
		{
			RpcBindingFree(&binding);
		}
	}

	RPC_BINDING_HANDLE binding = nullptr;
};
