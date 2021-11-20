#pragma once

#include <optional>

using OpNumFilter = std::optional<DWORD>;
using UUIDFilter = std::optional<std::wstring>;
using AddressFilter = std::optional<std::wstring>;

struct LineConfig
{
	UUIDFilter uuid;
	OpNumFilter opnum;
	AddressFilter source_addr;
	bool allow;
	bool audit;
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
