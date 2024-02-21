#include <cstdint>
#include <vector>
#include <cip/EPath.h>
#include <cip/Types.h>
#include "Common.h"


enum class SymbolClassAttributeNums : eipScanner::cip::CipUsint;

std::vector<uint8_t> makeRockwellMessage(
	eipScanner::cip::CipUsint service, const eipScanner::cip::EPath& path,
	std::vector<eipScanner::cip::CipUsint>& sybolClassAttributes,
	EPathSegmentTypes sendAdditionalPathSegment)
{
	std::vector<uint8_t> returnData;

	std::vector<uint8_t> ePathData;
	auto pathSize = path.getSizeInWords(true);
	if (pathSize == 0)
		return {0};
	auto pathBuf = path.packPaddedPath(true, true);
	ePathData.insert(ePathData.end(), pathBuf.begin(), pathBuf.end());

	if (path.getClassId() == 0x91)
	{
		ePathData.push_back(static_cast<uint8_t>(EPathSegmentTypes::CLASS_8_BITS));
		ePathData.push_back(static_cast<uint8_t>(0x6b));

		if (pathSize > 1)
		{
			ePathData.push_back(
				static_cast<uint8_t>(EPathSegmentTypes::INSTANCE_16_BITS));
			ePathData.push_back(0x00);

			uint8_t buf[2];
			auto objIdBuf = path.getObjectId();
			memcpy(&buf, &objIdBuf, sizeof(objIdBuf));
			ePathData.push_back(buf[0]);
			ePathData.push_back(buf[1]);
		}
	}

	std::vector<uint8_t> serviceCodesHead = {
		static_cast<uint8_t>(service),
		static_cast<uint8_t>(ePathData.size() / 2)
	};

	auto attributeCounts = static_cast<uint8_t>(sybolClassAttributes.size());

	std::vector<uint8_t> readAttributes = {attributeCounts, 0x00};

	for (auto attribute : sybolClassAttributes)
	{
		readAttributes.push_back(static_cast<uint8_t>(attribute));
		readAttributes.push_back(0x00);
	}

	std::vector<uint8_t> dataSize = {
		static_cast<uint8_t>(ePathData.size() + serviceCodesHead.size() +
			readAttributes.size()),
		0x00
	};

	uint8_t timeoutTicks = 0x01; //должно быть > 0
	uint8_t actualTimeout = 0xFF; //должно быть > 0
	std::vector<uint8_t> timeMessage = {actualTimeout, timeoutTicks};

	uint8_t routePathWords = 0x01;
	uint8_t linkAddress = 0x00;

	uint8_t pathSegmentType = 0x00;
	uint8_t extendedLinkAddress = 0x00;
	uint8_t routePathPort = 0x01;
	uint8_t routePathPEP = (0x0F & routePathPort) |
		(0x10 & (extendedLinkAddress << 4)) |
		(0xE0 & (pathSegmentType << 5));
	std::vector<uint8_t> routePath = {
		routePathWords,
		0x00, // reserved
		routePathPEP, linkAddress
	};

	returnData.insert(returnData.end(), timeMessage.begin(), timeMessage.end());
	returnData.insert(returnData.end(), dataSize.begin(), dataSize.end());
	returnData.insert(returnData.end(), serviceCodesHead.begin(),
	                  serviceCodesHead.end());
	returnData.insert(returnData.end(), ePathData.begin(), ePathData.end());
	returnData.insert(returnData.end(), readAttributes.begin(),
	                  readAttributes.end());
	returnData.insert(returnData.end(), routePath.begin(), routePath.end());
	return returnData;
}


std::vector<uint8_t> makeRockwellMessage(
	eipScanner::cip::CipUsint service, const eipScanner::cip::EPath& path,
	eipScanner::cip::CipUsint& sybolClassAttribute,
	EPathSegmentTypes sendAdditionalPathSegment)
{
	std::vector<eipScanner::cip::CipUsint> attribute(sybolClassAttribute);

	return makeRockwellMessage(service, path, attribute);
}
