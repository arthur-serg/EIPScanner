#include "Device.hpp"
#include "Common.h"
#include "capi/capi.h"


enum class SymbolClassAttributeNums : eipScanner::cip::CipUsint;
EIP_API EIP_ErrorCode ConnectDevice(char* hostname, size_t port)
{
#ifdef WIN32
	WSADATA wsaData;
	int winsockStart = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (winsockStart != 0)
	{
		return EIP_ErrorCode::RuntimeError;
	}
#endif
	Device device;
	if (!device.Connect(std::string(hostname), port))
		return EIP_ErrorCode::ConnectionFailed;

	else return EIP_ErrorCode::None;
}

EIP_API EIP_ErrorCode MakeRockwellMessage(uint8_t service, const ePath* epath,
                                          uint8_t symbolClassAttributes,
                                          uint8_t* buffer, uint8_t ePathSegmentTypes)
{
	/*
		SymbolClassAttributes attributes = symbolClassAttributes;
		std::memcpy(attributes.data(), symbolClassAttributes.data, symbolClassAttributes.size);
	*/

	auto message = makeRockwellMessage(
		service,
		eipScanner::cip::EPath(epath->classId, epath->objectId, epath->attributeId),
		symbolClassAttributes);

	std::memcpy(message.data(), buffer, message.size());

	return EIP_ErrorCode::None;
}


EIP_API EIP_ErrorCode MakeRockwellMessageTagString(uint8_t service, const ePath* epath,
                                                   eipScanner::cip::CipUsint symbolClassAttributes,
                                                   uint8_t* buffer, uint8_t ePathSegmentTypes)
{
	return EIP_ErrorCode::None;
}
