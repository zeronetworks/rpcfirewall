#pragma once

#include <optional>
#include <array>

struct AddressRangeIpv4 {
	uint32_t minAddr;
	uint32_t maxAddr;
};

struct AddressRangeIpv6 {
	std::array<UINT16,8> minAddr;
	std::array<UINT16,8> maxAddr;
};


struct AddressRange {
	std::optional<AddressRangeIpv4> ipv4;
	std::optional<AddressRangeIpv6> ipv6;
};

	
using OpNumFilter = std::optional<DWORD>;
using UUIDFilter = std::optional<std::wstring>;
using AddressRangeFilter = std::optional<AddressRange>;
using protocolFilter = std::optional<std::wstring>;
using SIDFilter = std::optional<std::wstring>;

struct RpcCallPolicy
{
	bool allow = true;
	bool audit = false;
};

struct LineConfig
{
	UUIDFilter uuid;
	OpNumFilter opnum;
	AddressRangeFilter addr;
	RpcCallPolicy policy;
	protocolFilter protocol;
	SIDFilter sid;
	bool verbose;
};

using ConfigVector = std::vector<LineConfig>;


class DoubleBufferedConfig
{
public:
	size_t getPassiveConfBufferNumber() const { return 1 - activeConfBufferNumber; }

	void changeActiveConfigurationNumber() { activeConfBufferNumber = getPassiveConfBufferNumber(); }

	const ConfigVector& getActiveConfigurationVector() const { return configVectors[activeConfBufferNumber]; }

	void setPassiveConfigurationVector(const ConfigVector& config) { configVectors[getPassiveConfBufferNumber()] = config; }

private:
	ConfigVector configVectors[2];
	size_t activeConfBufferNumber = 0;
};
