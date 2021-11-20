#pragma once

#include <optional>

using OpNumFilter = std::optional<DWORD>;
using UUIDFilter = std::optional<std::wstring>;
using AddressFilter = std::optional<std::wstring>;

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
