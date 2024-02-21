//
// Created by Aleksey Timin on 11/16/19.
//

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <winsock2.h>
#define OS_Windows (1)
#endif

#include "ConnectionManager.h"
#include "IdentityObject.h"
#include "SessionInfo.h"
#include "cip/MessageRouterRequest.h"
#include "cip/MessageRouterResponse.h"
#include "eip/CommonPacket.h"
#include "eip/CommonPacketItemFactory.h"
#include "eip/EncapsPacketFactory.h"
#include "utils/Buffer.h"
#include "utils/Logger.h"

#include "Device.hpp"
#include <DiscoveryManager.h>
#include <array>
#include <assert.h>
#include <cip/connectionManager/ForwardOpenRequest.h>
#include <cip/connectionManager/NetworkConnectionParams.h>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

using namespace eipScanner::cip;
using eipScanner::ConnectionManager;
using eipScanner::IdentityObject;
using eipScanner::MessageRouter;
using eipScanner::SessionInfo;
using eipScanner::SessionInfoIf;
using eipScanner::cip::MessageRouterRequest;
using eipScanner::cip::connectionManager::ConnectionParameters;
using eipScanner::cip::connectionManager::ForwardOpenRequest;
using eipScanner::cip::connectionManager::NetworkConnectionParams;
using eipScanner::eip::CommonPacket;
using eipScanner::eip::CommonPacketItemFactory;
using eipScanner::eip::EncapsCommands;
using eipScanner::eip::EncapsPacket;
using eipScanner::eip::EncapsPacketFactory;
using eipScanner::utils::Buffer;
using eipScanner::utils::Logger;
using eipScanner::utils::LogLevel;

enum class EPathSegmentTypes : CipUsint
{
	NONE = 0x00,
	CLASS_8_BITS = 0x20,
	CLASS_16_BITS = 0x21,
	INSTANCE_8_BITS = 0x24,
	INSTANCE_16_BITS = 0x25,
	ATTRIBUTE_8_BITS = 0x30,
	ATTRIBUTE_16_BITS = 0x31,
	ANSI_EXXTENDED_SYMBOL = 0x91,
};

enum class SymbolClassAttributeNums : CipUsint
{
	ATTRIBUTE_NAME = 0x01,
	ATTRIBUTE_TYPE = 0x02,
	ATTRIBUTE_UNKNOWN_1 = 0x07,
	ATTRIBUTE_UNKNOWN_2 = 0x08,
};

enum class TemplateObjectAttributeNums : CipUsint
{
	ATTRIBUTE_STRUCUTRE_HANDLE = 0x01,
	ATTRIBUTE_TEMPLATE_MEMBER_COUNT = 0x02,
	ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE = 0x04,
	ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE = 0x05,
};

typedef struct
{
	uint32_t instanceId;
	uint16_t symbolType;
	std::vector<uint8_t> name;
} ProgrammName;

struct StructuresInstace
{
	uint16_t instance;
	bool readed;

	StructuresInstace(uint16_t _instance, bool _readed)
		: instance(_instance), readed(_readed)
	{
	};

	friend bool operator<(const StructuresInstace& x,
	                      const StructuresInstace& y)
	{
		return x.instance < y.instance;
	}
};


/*struct IaMassivcheg
{
	uint8_t* data;
	uint64_t size;
};

IaMassivcheg makeRockwellMessageTest(
	some args
)
{
	auto& result = makeRockwellMessageTest(
		args
	);
	return {result.data, result.size()};
}*/

//std::vector<uint8_t> makeRockwellMessageTest(
//	CipUsint service, const EPath& path,
//	SymbolClassAttributeNums& sybolClassAttribute,
//	EPathSegmentTypes sendAdditionalPathSegment = EPathSegmentTypes::NONE)
//{
//	return makeRockwellMessageTest(service, path, {sybolClassAttribute});
//}


std::vector<uint8_t> makeRockwellMessageTest(
	CipUsint service, const EPath& path,
	std::vector<SymbolClassAttributeNums>& sybolClassAttributes,
	EPathSegmentTypes sendAdditionalPathSegment = EPathSegmentTypes::NONE)
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

	uint8_t attributeCounts = sybolClassAttributes.size();

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


//uint64_t makeRockwellMessageTest(
//	CipUsint service, const EPath& path,
//	std::vector<SymbolClassAttributeNums>& sybolClassAttributes,
//	uint8_t* buffer
//)
//{
//	auto result = makeRockwellMessageTest(
//		service, path, sybolClassAttributes, EPathSegmentTypes::NONE
//	);
//	std::copy(buffer, result.data(), result.size());
//	return result.size();
//}

uint32_t parseRocwellSybolClassResponse(
	const std::vector<uint8_t>& data,
	std::vector<SymbolClassAttributeNums>& sybolClassAttributes,
	std::vector<ProgrammName>& progsName,
	std::set<StructuresInstace>& structuresInstace)
{
	uint32_t instanceId = 0;
	uint16_t symbolType;
	uint16_t nameLenght;
	std::string name;
	uint16_t attrUnk1;
	std::array<uint8_t, 12> attrUnk2;
	std::size_t i = 0;
	while (i < data.size())
	{
		instanceId = data[i++];
		instanceId |= data[i++] << 8;
		instanceId |= data[i++] << 16;
		instanceId |= data[i++] << 24;

		std::cout << "instanceId: "
			<< "0x" << std::hex << std::setfill('0') << std::setw(8)
			<< instanceId << "\n";

		for (auto attribute : sybolClassAttributes)
		{
			switch (attribute)
			{
			case SymbolClassAttributeNums::ATTRIBUTE_NAME:
				name.clear();
				nameLenght = data[i++];
				nameLenght |= data[i++] << 8;
				for (uint16_t j = 0; j < nameLenght; ++j)
				{
					name += data[i++];
				}
				std::cout << "nameLenght: "
					<< "0x" << std::hex << std::setfill('0') << std::setw(4)
					<< static_cast<int>(nameLenght) << "\n\t";
				std::cout << "name: " << name << "\n";
				break;

			case SymbolClassAttributeNums::ATTRIBUTE_TYPE:
				symbolType = data[i++];
				symbolType |= data[i++] << 8;
				std::cout << "symbolType: "
					<< "0x" << std::hex << std::setfill('0') << std::setw(4)
					<< static_cast<int>(symbolType) << "\n";
				break;

			case SymbolClassAttributeNums::ATTRIBUTE_UNKNOWN_1:
				attrUnk1 = data[i++];
				attrUnk1 |= data[i++] << 8;
				std::cout << "attrUnk1: "
					<< "0x" << std::hex << std::setfill('0') << std::setw(4)
					<< static_cast<int>(attrUnk1) << "\n";
				break;

			case SymbolClassAttributeNums::ATTRIBUTE_UNKNOWN_2:
				for (auto& b : attrUnk2)
				{
					b = data[i++];
				}
				std::cout << "attrUnk2: ";
				for (auto b : attrUnk2)
				{
					std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
						<< static_cast<int>(b) << " ";
				}
				std::cout << "\n";
				break;

			default:
				break;
			}
		}

		if (symbolType == 0x1068)
		{
			ProgrammName progName = {
				instanceId, symbolType,
				std::vector<uint8_t>(name.begin(), name.end())
			};
			progsName.push_back(progName);
		}

		if (symbolType & 0x8000)
		{
			structuresInstace.insert(StructuresInstace(symbolType & 0x0FFF, false));
		}
	}

	std::cout << std::endl;
	return instanceId; // last Instace ID
}

uint32_t parseRocwellSybolClassResponse(
	const std::vector<uint8_t>& data,
	std::vector<SymbolClassAttributeNums>& sybolClassAttributes,
	std::vector<ProgrammName>& progsName)
{
	std::set<StructuresInstace> structuresInstace;
	return parseRocwellSybolClassResponse(data, sybolClassAttributes, progsName,
	                                      structuresInstace);
}

uint32_t parseRocwellSybolClassResponse(
	const std::vector<uint8_t>& data,
	std::vector<SymbolClassAttributeNums>& sybolClassAttributes,
	std::set<StructuresInstace>& structuresInstace)
{
	std::vector<ProgrammName> progsName;
	return parseRocwellSybolClassResponse(data, sybolClassAttributes, progsName,
	                                      structuresInstace);
}

uint32_t parseRocwellSybolClassResponse(
	const std::vector<uint8_t>& data,
	std::vector<SymbolClassAttributeNums>& sybolClassAttributes)
{
	std::vector<ProgrammName> progsName;
	return parseRocwellSybolClassResponse(data, sybolClassAttributes, progsName);
}

typedef struct
{
	uint16_t status;

	union
	{
		uint16_t value16;
		uint32_t value32;
	};
} TemplateObjectResponse;

std::array<uint32_t, 2>
parseRocwellTemplateObjectResponse(const std::vector<uint8_t>& data)
{
	TemplateObjectResponse structureHandle;
	TemplateObjectResponse templateMemberCount;
	TemplateObjectResponse templateObjectDefinitionSize;
	TemplateObjectResponse templateStructureSize;

	std::array<uint32_t, 2> retData;

	uint16_t attributesCount = 0x00;
	uint16_t attribute = 0x00;

	std::size_t i = 0;

	attributesCount = data[i++];
	attributesCount |= data[i++] << 8;

	for (uint16_t j = 0; j < attributesCount; j++)
	{
		attribute = data[i++];
		attribute |= data[i++] << 8;
		switch (static_cast<TemplateObjectAttributeNums>(attribute))
		{
		case TemplateObjectAttributeNums::ATTRIBUTE_STRUCUTRE_HANDLE:
			structureHandle.status = data[i++];
			structureHandle.status |= data[i++] << 8;
			structureHandle.value16 = data[i++];
			structureHandle.value16 |= data[i++] << 8;
			std::cout << "structureHandle:\n";
			std::cout << "\tstatus:  0x" << std::hex << std::setfill('0')
				<< std::setw(4) << static_cast<int>(structureHandle.status)
				<< "\n";
			std::cout << "\tvalue16: 0x" << std::hex << std::setfill('0')
				<< std::setw(4) << static_cast<int>(structureHandle.value16)
				<< "\n";
			break;

		case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_MEMBER_COUNT:
			templateMemberCount.status = data[i++];
			templateMemberCount.status |= data[i++] << 8;
			templateMemberCount.value16 = data[i++];
			templateMemberCount.value16 |= data[i++] << 8;
			std::cout << "templateMemberCount:\n";
			std::cout << "\tstatus:  0x" << std::hex << std::setfill('0')
				<< std::setw(4) << static_cast<int>(templateMemberCount.status)
				<< "\n";
			std::cout << "\tvalue16: 0x" << std::hex << std::setfill('0')
				<< std::setw(4) << static_cast<int>(templateMemberCount.value16)
				<< "\n";
			break;

		case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE:
			templateObjectDefinitionSize.status = data[i++];
			templateObjectDefinitionSize.status |= data[i++] << 8;
			templateObjectDefinitionSize.value32 = data[i++];
			templateObjectDefinitionSize.value32 |= data[i++] << 8;
			templateObjectDefinitionSize.value32 |= data[i++] << 16;
			templateObjectDefinitionSize.value32 |= data[i++] << 24;
			std::cout << "templateObjectDefinitionSize:\n";
			std::cout << "\tstatus:  0x" << std::hex << std::setfill('0')
				<< std::setw(4)
				<< static_cast<int>(templateObjectDefinitionSize.status)
				<< "\n";
			std::cout << "\tvalue32: 0x" << std::hex << std::setfill('0')
				<< std::setw(8)
				<< static_cast<int>(templateObjectDefinitionSize.value32)
				<< "\n";
			break;

		case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE:
			templateStructureSize.status = data[i++];
			templateStructureSize.status |= data[i++] << 8;
			templateStructureSize.value32 = data[i++];
			templateStructureSize.value32 |= data[i++] << 8;
			templateStructureSize.value32 |= data[i++] << 16;
			templateStructureSize.value32 |= data[i++] << 24;
			std::cout << "templateStructureSize:\n";
			std::cout << "\tstatus:  0x" << std::hex << std::setfill('0')
				<< std::setw(4)
				<< static_cast<int>(templateStructureSize.status) << "\n";
			std::cout << "\tvalue32: 0x" << std::hex << std::setfill('0')
				<< std::setw(8)
				<< static_cast<int>(templateStructureSize.value32) << "\n";
			break;

		default:
			break;
		}
	}

	std::cout << std::endl;
	retData[0] = (templateObjectDefinitionSize.value32 * 4) -
		23; // The number of bytes to be read
	retData[1] = templateMemberCount.value16;
	return retData;
}

enum class TagTypeValue : uint16_t
{
	BOOL = 0x00C1,
	SINT = 0x00C2,
	INT = 0x00C3,
	DINT = 0x00C4,
	REAL = 0x00CA,
	DWORD = 0x00D3,
	LINT = 0x00C5,
};

std::string getTypecodeString(uint16_t typeCode)
{
	if (0x8000 & typeCode)
	{
		return "STRUCT";
	}

	switch (static_cast<TagTypeValue>(typeCode & 0x00FF))
	{
	case TagTypeValue::BOOL:
		return "BOOL";
		break;
	case TagTypeValue::SINT:
		return "SINT";
		break;
	case TagTypeValue::INT:
		return "INT";
		break;
	case TagTypeValue::DINT:
		return "DINT";
		break;
	case TagTypeValue::REAL:
		return "REAL";
		break;
	case TagTypeValue::DWORD:
		return "DWORD";
		break;
	case TagTypeValue::LINT:
		return "LINT";
		break;

	default:
		return "";
		break;
	}

	return "";
}

void parseRocwellStructResponse(const std::vector<uint8_t>& data,
                                uint32_t elementsCount)
{
	uint16_t arraySize = 0x0000;
	uint16_t typeCode = 0x0000;
	uint32_t offset = 0x00000000;

	uint32_t i = 0;

	std::cout << "parseRocwellStructResponse\n";

	for (uint32_t j = 0; j < elementsCount; j++)
	{
		arraySize = data[i++];
		arraySize |= data[i++] << 8;

		typeCode = data[i++];
		typeCode |= data[i++] << 8;

		offset = data[i++];
		offset |= data[i++] << 8;
		offset |= data[i++] << 16;
		offset |= data[i++] << 24;

		std::cout << "element " << j << " " << getTypecodeString(typeCode) << "\n";
		std::cout << "\taraySize: 0x" << std::hex << std::setfill('0')
			<< std::setw(4) << static_cast<int>(arraySize) << "\n";
		std::cout << "\ttypeCode: 0x" << std::hex << std::setfill('0')
			<< std::setw(4) << static_cast<int>(typeCode) << "\n";
		std::cout << "\toffset:   0x" << std::hex << std::setfill('0')
			<< std::setw(8) << offset << "\n";
		std::cout << std::endl;
	}
}

enum class CalssType : CipUint
{
	CONNECTION_MANAGER_CLASS = 0x06,
	SYMBOL_CLASS = 0x6b,
	TEMPLATE_OBJECT = 0x6c,
	ANSI_EXTENDED_SYMBOLIC = 0x91,
};

int main()
{
	Logger::setLogLevel(LogLevel::DEBUG);

start:

#if OS_Windows
	WSADATA wsaData;
	int winsockStart = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (winsockStart != 0)
	{
		Logger(LogLevel::ERROR)
			<< "Failed to start WinSock - error code: " << winsockStart;
		return EXIT_FAILURE;
	}
#endif

	const std::string hostname = "192.168.1.100";
	const int port = 0xaf12;

	eipScanner::DiscoveryManager discoveryManager(hostname, port,
	                                              std::chrono::seconds(1));
	auto devices = discoveryManager.discover();

	for (const auto& device : devices)
	{
		Logger(LogLevel::INFO) << "Discovered device: "
			<< device.identityObject.getProductName()
			<< " with address "
			<< device.socketAddress.toString();
	}

	if (true)
	{
		Device RockwellDevice;

		if (RockwellDevice.Connect(hostname, port))
		{
			IdentityObject identityObject(1, RockwellDevice.getSi());

			Logger(LogLevel::INFO)
				<< identityObject.getVendorId() << " "
				<< identityObject.getDeviceType() << " "
				<< identityObject.getProductCode() << " "
				<< identityObject.getRevision().toString() << " "
				<< identityObject.getStatus() << identityObject.getSerialNumber()
				<< "\n " << identityObject.getProductName() << " ";

			//считываемые атрибуты
			std::vector<SymbolClassAttributeNums> sybolClassAttributes = {
				SymbolClassAttributeNums::ATTRIBUTE_TYPE,
				SymbolClassAttributeNums::ATTRIBUTE_NAME
			};

			uint32_t instaceId = 0x00; //смещение
			//отправка безконектных сообщений сообщения
			//читаем имена программ
			std::vector<ProgrammName> progsName;
			for (;;)
			{
				auto rockwellMessage = makeRockwellMessageTest(
					ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST,
					EPath(static_cast<CipUint>(CalssType::SYMBOL_CLASS), instaceId),
					sybolClassAttributes);

				auto response = RockwellDevice.getMessageRouter()->sendRequest(
					RockwellDevice.getSi(), ServiceCodes::READ_TAG_FRAGMENTED,
					EPath(static_cast<CipUint>(CalssType::CONNECTION_MANAGER_CLASS),
					      0x01),
					rockwellMessage);

				instaceId = parseRocwellSybolClassResponse(
						response.getData(), sybolClassAttributes, progsName) +
					1;

				if (PARTIAL_TRANSFER != response.getGeneralStatusCode())
				{
					break;
				}
			}

			//читаем имена структур
			std::set<StructuresInstace> structuresInstace;
			for (auto progName : progsName)
			{
				instaceId = 0x00;
				for (;;)
				{
					auto rockwellMessage = makeRockwellMessageTest(
						ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST,
						EPath(static_cast<CipUint>(CalssType::ANSI_EXTENDED_SYMBOLIC),
						      progName.name, instaceId),
						sybolClassAttributes);
					auto response = RockwellDevice.getMessageRouter()->sendRequest(
						RockwellDevice.getSi(), ServiceCodes::READ_TAG_FRAGMENTED,
						EPath(static_cast<CipUint>(CalssType::CONNECTION_MANAGER_CLASS),
						      0x01),
						rockwellMessage);

					instaceId = parseRocwellSybolClassResponse(response.getData(),
					                                           sybolClassAttributes,
					                                           structuresInstace) +
						1;

					if (PARTIAL_TRANSFER != response.getGeneralStatusCode())
					{
						break;
					}
				}
			}

			instaceId = 0x00;
			// вслучае обрыва соединения надо заново все проинитить
			// для проверки востановления соединения поменять на while (1)

			while (0)
			{
				auto rockwellMessage = makeRockwellMessageTest(
					ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST,
					EPath(static_cast<CipUint>(CalssType::ANSI_EXTENDED_SYMBOLIC),
					      progsName[0].name, instaceId),
					sybolClassAttributes);
				try
				{
					auto response = RockwellDevice.getMessageRouter()->sendRequest(
						RockwellDevice.getSi(), ServiceCodes::READ_TAG_FRAGMENTED,
						EPath(static_cast<CipUint>(CalssType::CONNECTION_MANAGER_CLASS),
						      0x01),
						rockwellMessage);
				}
				catch (...)
				{
					std::cout << "error\n";
					goto start;
				}
			}

			//отправка конектных сообщений

			uint16_t sequenceCount = 0x00;

			// необходимо инкреминтировать для корректной отправкии
			//     сообщений
			//запись и чтение данных в тег по имени тега, также можно и по id
			std::cout << "tag test_sint WRITE\n";
			std::string stringTag = "test_sint";
			std::vector<uint8_t> elementsToWrite = {
				0xC2, 0x00, 0x01, 0x00, 0x0E,
				0x00
			};
			// |           |           |
			// TYPE         |           |
			// int 2 bytes  |           |
			//             |           |
			// quantity of elements    |
			//                         |
			//                       value

			if (auto ptr = RockwellDevice.getIo().lock())
			{
				auto response = ptr->sendUnit(
					RockwellDevice.getSi(), ServiceCodes::WRITE_TAG,
					EPath(static_cast<CipUint>(CalssType::ANSI_EXTENDED_SYMBOLIC),
					      std::vector<uint8_t>(stringTag.begin(), stringTag.end()),
					      0x0000),
					elementsToWrite);

				for (auto data : response.data)
				{
					std::cout << "0x" << std::hex << static_cast<int>(data) << " ";
				}

				std::cout << std::endl;
			}

			std::cout << "tag testbool READ\n";
			stringTag = "testbool";

			std::vector<uint8_t> elementsToRead = {0x01, 0x00};
			if (auto ptr = RockwellDevice.getIo().lock())
			{
				auto response = ptr->sendUnit(
					RockwellDevice.getSi(), ServiceCodes::READ_TAG,
					EPath(static_cast<CipUint>(CalssType::ANSI_EXTENDED_SYMBOLIC),
					      std::vector<uint8_t>(stringTag.begin(), stringTag.end()),
					      0x0000),
					elementsToRead);
				for (auto data : response.data)
				{
					std::cout << "0x" << std::hex << static_cast<int>(data) << " ";
				}

				std::cout << std::endl;
			}

			std::cout << "READ STRUCTURES\n";

			std::vector<uint8_t> templateObjectPacket{
				0x04,
				0x00, // attributes count
				static_cast<uint8_t>(
					TemplateObjectAttributeNums::ATTRIBUTE_STRUCUTRE_HANDLE),
				0x00,
				static_cast<uint8_t>(
					TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_MEMBER_COUNT),
				0x00,
				static_cast<uint8_t>(TemplateObjectAttributeNums::
					ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE),
				0x00,
				static_cast<uint8_t>(
					TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE),
				0x00
			};

			//разбор структур на теги и вложенные структуры
			for (auto& sctructInstance : structuresInstace)
			{
				std::cout << "READ STRUCTURES1\n";
				if (auto ptr = RockwellDevice.getIo().lock())
				{
					auto response = ptr->sendUnit(
						RockwellDevice.getSi(), ServiceCodes::GET_ATTRIBUTE_LIST,
						EPath(static_cast<CipUint>(CalssType::TEMPLATE_OBJECT),
						      sctructInstance.instance),
						templateObjectPacket);
					auto parsedData =
						parseRocwellTemplateObjectResponse(response.data);

					uint32_t readBytes = parsedData[0];
					std::cout << std::endl;
					std::cout << "readBytes = 0x" << std::hex << std::setfill('0')
						<< std::setw(8) << std::hex << readBytes << "\n";
					std::vector<uint8_t> readBytesPack = {
						0x00,
						0x00,
						0x00,
						0x00, // always 0
						static_cast<uint8_t>(readBytes & 0x000000FF),
						static_cast<uint8_t>((readBytes & 0x0000FF00) >> 8)
					};

					if (response.status != 0x00)
					{
						break;
					}

					std::cout << "READ_TAG\n";
					response =
						ptr->sendUnit(RockwellDevice.getSi(), ServiceCodes::READ_TAG,
						              EPath(0x6C, sctructInstance.instance),
						              readBytesPack);
					//парсим типы и офсеты, также там присутствуют имена тегов, но я не
					//понял
					//как их нормально парсить.
					parseRocwellStructResponse(response.data, parsedData[1]);
				}
			}

			auto count = 10;
			while (RockwellDevice.getConnectionManager().hasOpenConnections() &&
				count-- > 0)
			{
				RockwellDevice.getConnectionManager().handleConnections(
					std::chrono::milliseconds(100));
			}
			RockwellDevice.getConnectionManager().forwardClose(
				RockwellDevice.getSi(), RockwellDevice.getIo());
		}
#if OS_Windows
		WSACleanup();
#endif

		return EXIT_SUCCESS;
	}
}
