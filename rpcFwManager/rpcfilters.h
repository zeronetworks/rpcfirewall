#pragma once
#include <optional>

using OpNumFilter = std::optional<DWORD>;
using UUIDFilter = std::optional<std::wstring>;
using AddressFilter = std::optional<std::wstring>;
using SIDFilter = std::optional<std::wstring>;
using protocolFilter = std::optional<std::wstring>;

struct RpcCallPolicy
{
	bool allow = true;
	bool audit = false;
};

struct LineConfig
{
	UUIDFilter uuid;
	OpNumFilter opnum;
	AddressFilter source_addr;
	RpcCallPolicy policy;
	SIDFilter sid;
	protocolFilter protocol;
	bool verbose;
};

typedef std::vector<std::pair<std::wstring, LineConfig>> configLinesVector;

void enableAuditingForRPCFilters();

void disableAuditingForRPCFilters();

void createIPBlockRPCFilter(std::string);

void deleteAllRPCFilters();

void installRPCFWProvider();

void createRPCFilterFromTextLines(configLinesVector);

void printAllRPCFilters();

bool isProviderInstalled();

bool isAuditingEnabledForRPCFilters();
