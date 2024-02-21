//
// Created by Aleksey Timin on 11/16/19.
//

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <winsock2.h>
#define OS_Windows (1)
#endif

#include <sstream>
#include <assert.h>
#include <cip/connectionManager/NetworkConnectionParams.h>
#include <cip/connectionManager/ForwardOpenRequest.h>
#include "cip/MessageRouterRequest.h"
#include "cip/MessageRouterResponse.h"
#include "eip/CommonPacketItemFactory.h"
#include "eip/CommonPacket.h"
#include "SessionInfo.h"
#include "ConnectionManager.h"
#include "utils/Logger.h"
#include "utils/Buffer.h"
#include "IdentityObject.h"
#include "eip/EncapsPacketFactory.h"
#include <iostream>
#include <iomanip>
#include <set>

using namespace eipScanner::cip;
using eipScanner::IdentityObject;
using eipScanner::SessionInfo;
using eipScanner::SessionInfoIf;
using eipScanner::MessageRouter;
using eipScanner::ConnectionManager;
using eipScanner::cip::connectionManager::ConnectionParameters;
using eipScanner::cip::connectionManager::NetworkConnectionParams;
using eipScanner::cip::connectionManager::ForwardOpenRequest;
using eipScanner::cip::MessageRouterRequest;
using eipScanner::utils::Buffer;
using eipScanner::utils::Logger;
using eipScanner::utils::LogLevel;
using eipScanner::eip::EncapsPacket;
using eipScanner::eip::EncapsCommands;
using eipScanner::eip::CommonPacketItemFactory;
using eipScanner::eip::CommonPacket;
using eipScanner::eip::EncapsPacketFactory;


enum class EPathSegmentTypes : CipUsint {
  NONE = 0x00,
  CLASS_8_BITS = 0x20,
  CLASS_16_BITS = 0x21,
  INSTANCE_8_BITS = 0x24,
  INSTANCE_16_BITS = 0x25,
  ATTRIBUTE_8_BITS = 0x30,
  ATTRIBUTE_16_BITS = 0x31,
  ANSI_EXXTENDED_SYMBOL = 0x91,
};

enum class SybolClassAttributeNums : CipUsint {
  ATTRIBUTE_NAME = 0x01,
  ATTRIBUTE_TYPE = 0x02,
  ATTRIBUTE_UNKNOWN_1 = 0x07,
  ATTRIBUTE_UNKNOWN_2 = 0x08,
};

enum class TemplateObjectAttributeNums : CipUsint {
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
  StructuresInstace(uint16_t _instance, bool _readed) : instance(_instance), readed(_readed) {};
  friend bool operator<(const StructuresInstace& x, const StructuresInstace& y) {
    return x.instance < y.instance;
  }
};

std::vector<uint8_t> makeRockwellMessage(CipUsint service, const EPath& path, std::vector<SybolClassAttributeNums>& sybolClassAttributes, EPathSegmentTypes sendAdditionalPathSegment=EPathSegmentTypes::NONE) {
  std::vector<uint8_t> returnData;

  std::vector<uint8_t> ePathData;
  auto pathSize = path.getSizeInWords(true);
  if (pathSize == 0)
    return {0};
  auto pathBuf = path.packPaddedPath(true, true);
  ePathData.insert(ePathData.end(), pathBuf.begin(), pathBuf.end());

  if (path.getClassId() == 0x91) {
    ePathData.push_back(static_cast<uint8_t>(EPathSegmentTypes::CLASS_8_BITS));
    ePathData.push_back(static_cast<uint8_t>(0x6b));

    if (pathSize > 1) {
      ePathData.push_back(static_cast<uint8_t>(EPathSegmentTypes::INSTANCE_16_BITS));
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
    static_cast<uint8_t>(ePathData.size()/2)
  };

  uint8_t attributeCounts = sybolClassAttributes.size();

  std::vector<uint8_t> readAttributes = {
    attributeCounts, 0x00
  };

  for (auto attribute : sybolClassAttributes) {
    readAttributes.push_back(static_cast<uint8_t>(attribute));
    readAttributes.push_back(0x00);
  }

  std::vector<uint8_t> dataSize = {
    static_cast<uint8_t>(ePathData.size() + serviceCodesHead.size() + readAttributes.size()),
    0x00
  };

  uint8_t timeoutTicks  = 0x01; //должно быть > 0
  uint8_t actualTimeout = 0xFF; //должно быть > 0
  std::vector<uint8_t> timeMessage = { actualTimeout, timeoutTicks };

  uint8_t routePathWords      = 0x01;
  uint8_t linkAddress         = 0x00;

  uint8_t pathSegmentType     = 0x00;
  uint8_t extendedLinkAddress = 0x00;
  uint8_t routePathPort       = 0x01;
  uint8_t routePathPEP        = (0x0F & routePathPort) | (0x10 & (extendedLinkAddress << 4)) | (0xE0 & (pathSegmentType << 5));
  std::vector<uint8_t> routePath = {
    routePathWords,
    0x00, //reserved
    routePathPEP,
    linkAddress
  };

  returnData.insert(returnData.end(), timeMessage.begin(),      timeMessage.end());
  returnData.insert(returnData.end(), dataSize.begin(),         dataSize.end());
  returnData.insert(returnData.end(), serviceCodesHead.begin(), serviceCodesHead.end());
  returnData.insert(returnData.end(), ePathData.begin(),        ePathData.end());
  returnData.insert(returnData.end(), readAttributes.begin(),   readAttributes.end());
  returnData.insert(returnData.end(), routePath.begin(),        routePath.end());
  return returnData;
}

EncapsPacket createSendUnitDataPacket(CipUdint sessionHandle, CipUint timeout, std::vector<uint8_t> data) {
  EncapsPacket packet;
  packet.setCommand(EncapsCommands::SEND_UNIT_DATA);
  packet.setSessionHandle(sessionHandle);

  CipUdint interfaceHandle = 0;
  Buffer buffer(6 + data.size());
  buffer << interfaceHandle << timeout << data;
  packet.setData(buffer.data());

  return packet;
}

struct MessageUnitResponse {
  uint32_t interfaceHandle;
  uint16_t timeout;
  uint16_t itemCount;
  uint16_t connectedAddressItem;
  uint16_t connectionIdLenght;
  uint32_t connectionId;
  uint16_t connectedDataItem;
  uint16_t connectedDataItemLenght;
  uint16_t sequenceCount;
  uint8_t  service;
  uint8_t  reserved;
  uint16_t status;
  std::vector<uint8_t> data;
};

MessageUnitResponse sendUnit(SessionInfoIf::SPtr si, CipUsint service, const EPath &path, const std::vector<uint8_t> &data, CipUdint _o2tNetworkConnectionId, uint16_t _sequenceCount) {
  assert(si);
  MessageUnitResponse response;
  MessageRouterRequest request{service, path, data, false, true};

  CommonPacketItemFactory commonPacketItemFactory;
  CommonPacket commonPacket;
  commonPacket << commonPacketItemFactory.createConnectedAddressItem(_o2tNetworkConnectionId);

  auto packBuf = request.pack();

  std::vector<uint8_t> sequenceCount = {
    static_cast<uint8_t>(_sequenceCount & 0x00FF),
    static_cast<uint8_t>((_sequenceCount & 0xFF00) >> 8)
  };
  sequenceCount.insert(sequenceCount.end(), packBuf.begin(), packBuf.end());
  commonPacket << commonPacketItemFactory.createConnectedDataItem(sequenceCount);

  auto packetToSend = createSendUnitDataPacket(si->getSessionHandle(), 0, commonPacket.pack());

  auto receivedData = si->sendAndReceive(packetToSend).getData();

  uint32_t i = 0;

  response.interfaceHandle  = receivedData[i++];
  response.interfaceHandle |= receivedData[i++] << 8;
  response.interfaceHandle |= receivedData[i++] << 16;
  response.interfaceHandle |= receivedData[i++] << 24;

  response.timeout  = receivedData[i++];
  response.timeout |= receivedData[i++] << 8;

  response.itemCount  = receivedData[i++];
  response.itemCount |= receivedData[i++] << 8;

  response.connectedAddressItem  = receivedData[i++];
  response.connectedAddressItem |= receivedData[i++] << 8;

  response.connectionIdLenght  = receivedData[i++];
  response.connectionIdLenght |= receivedData[i++] << 8;

  response.connectionId  = receivedData[i++];
  response.connectionId |= receivedData[i++] << 8;
  response.connectionId |= receivedData[i++] << 16;
  response.connectionId |= receivedData[i++] << 24;

  response.connectedDataItem  = receivedData[i++];
  response.connectedDataItem |= receivedData[i++] << 8;

  response.connectedDataItemLenght  = receivedData[i++];
  response.connectedDataItemLenght |= receivedData[i++] << 8;

  response.sequenceCount  = receivedData[i++];
  response.sequenceCount |= receivedData[i++] << 8;

  response.service  = receivedData[i++];
  response.reserved = receivedData[i++];

  response.status  = receivedData[i++];
  response.status |= receivedData[i++] << 8;

  response.data.insert(response.data.end(), receivedData.begin() + i, receivedData.end());

  return response;
}



std::vector<uint8_t> makeUnit(SessionInfoIf::SPtr si, CipUsint service, const EPath &path, const std::vector<uint8_t> &data, CipUdint _o2tNetworkConnectionId, CipUdint _o2tSequenceNumber = 0x00) {
  assert(si);
  Logger(LogLevel::INFO) << "Send request: service=0x" << std::hex << static_cast<int>(service)
                         << " epath=" << path.toString();
  MessageRouterRequest request{service, path, data, false, true};

  Logger(LogLevel::INFO) << "commonPacketItemFactory";
  CommonPacketItemFactory commonPacketItemFactory;
  Logger(LogLevel::INFO) << "commonPacket";
  CommonPacket commonPacket;
  commonPacket << commonPacketItemFactory.createConnectedAddressItem(_o2tNetworkConnectionId);

  auto packBuf = request.pack();
  std::vector<uint8_t> sequenceCount = { 0x4a, 0x00 };
  sequenceCount.insert(sequenceCount.end(), packBuf.begin(), packBuf.end());
  commonPacket << commonPacketItemFactory.createConnectedDataItem(sequenceCount);

  Logger(LogLevel::INFO) << "createSendUnitDataPacket";
  auto packetToSend = createSendUnitDataPacket(si->getSessionHandle(), 0, commonPacket.pack());
  Logger(LogLevel::INFO) << "sendAndReceive";
  Logger(LogLevel::INFO) << std::hex << static_cast<int>(packetToSend.pack().size());
  for (auto data : packetToSend.pack()) {
    std::cout << "0x" << std::hex << static_cast<int>(data) << " ";
  }
  return packetToSend.pack();
}

uint32_t parseRocwellSybolClassResponse(const std::vector<uint8_t>& data, std::vector<SybolClassAttributeNums>& sybolClassAttributes, std::vector<ProgrammName>& progsName, std::set<StructuresInstace>& structuresInstace) {
  uint32_t instanceId;
  uint16_t symbolType;
  uint16_t nameLenght;
  std::string name;
  uint16_t attrUnk1;
  std::array<uint8_t, 12> attrUnk2;
  std::size_t i = 0;
  while (i < data.size()) {
    instanceId = data[i++];
    instanceId |= data[i++] << 8;
    instanceId |= data[i++] << 16;
    instanceId |= data[i++] << 24;

    std::cout << "instanceId: " << "0x" << std::hex << std::setfill('0') << std::setw(8) << instanceId << "\n";
  
    for (auto attribute : sybolClassAttributes) {
      switch (attribute)
      {
      case SybolClassAttributeNums::ATTRIBUTE_NAME:
          name.clear();
          nameLenght = data[i++];
          nameLenght |= data[i++] << 8;
          for (uint16_t j = 0; j < nameLenght; ++j) {
            name+=data[i++];
          }
          std::cout << "nameLenght: " << "0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(nameLenght) << "\n\t";
          std::cout << "name: " << name << "\n";
        break;
      
      case SybolClassAttributeNums::ATTRIBUTE_TYPE:
          symbolType = data[i++];
          symbolType |= data[i++] << 8;
          std::cout << "symbolType: " << "0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(symbolType) << "\n";
        break;

      case SybolClassAttributeNums::ATTRIBUTE_UNKNOWN_1:
          attrUnk1 = data[i++];
          attrUnk1 |= data[i++] << 8;
          std::cout << "attrUnk1: " << "0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(attrUnk1) << "\n";
        break;

      case SybolClassAttributeNums::ATTRIBUTE_UNKNOWN_2:
          for(auto& b : attrUnk2) {
            b = data[i++];
          }
          std::cout << "attrUnk2: ";
          for(auto b : attrUnk2) {
            std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b) << " ";
          }
          std::cout << "\n";
        break;

      default:
        break;
      }
    }

    if (symbolType == 0x1068) {
      ProgrammName progName = {
        instanceId,
        symbolType,
        std::vector<uint8_t> (name.begin(), name.end())
      };
      progsName.push_back(progName);
    }
  
    if (symbolType & 0x8000) {
      structuresInstace.insert(StructuresInstace(symbolType & 0x0FFF, false));
    }
  }

  std::cout << std::endl;
  return instanceId; //last Instace ID
}

uint32_t parseRocwellSybolClassResponse(const std::vector<uint8_t>& data, std::vector<SybolClassAttributeNums>& sybolClassAttributes, std::vector<ProgrammName>& progsName) {
  std::set<StructuresInstace> structuresInstace;
  return parseRocwellSybolClassResponse(data, sybolClassAttributes, progsName, structuresInstace);
}

uint32_t parseRocwellSybolClassResponse(const std::vector<uint8_t>& data, std::vector<SybolClassAttributeNums>& sybolClassAttributes, std::set<StructuresInstace>& structuresInstace) {
  std::vector<ProgrammName> progsName;
  return parseRocwellSybolClassResponse(data, sybolClassAttributes, progsName, structuresInstace);
}

uint32_t parseRocwellSybolClassResponse(const std::vector<uint8_t>& data, std::vector<SybolClassAttributeNums>& sybolClassAttributes) {
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

std::array<uint32_t, 2> parseRocwellTemplateObjectResponse(const std::vector<uint8_t>& data) {
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
  
  for (uint16_t j = 0; j < attributesCount; j++) {
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
        std::cout << "\tstatus:  0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(structureHandle.status) << "\n";
        std::cout << "\tvalue16: 0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(structureHandle.value16) << "\n";
      break;
    
    case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_MEMBER_COUNT:
        templateMemberCount.status = data[i++];
        templateMemberCount.status |= data[i++] << 8;
        templateMemberCount.value16 = data[i++];
        templateMemberCount.value16 |= data[i++] << 8;
        std::cout << "templateMemberCount:\n";
        std::cout << "\tstatus:  0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(templateMemberCount.status) << "\n";
        std::cout << "\tvalue16: 0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(templateMemberCount.value16) << "\n";
      break;

    case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE:
        templateObjectDefinitionSize.status = data[i++];
        templateObjectDefinitionSize.status |= data[i++] << 8;
        templateObjectDefinitionSize.value32 = data[i++];
        templateObjectDefinitionSize.value32 |= data[i++] << 8;
        templateObjectDefinitionSize.value32 |= data[i++] << 16;
        templateObjectDefinitionSize.value32 |= data[i++] << 24;
        std::cout << "templateObjectDefinitionSize:\n";
        std::cout << "\tstatus:  0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(templateObjectDefinitionSize.status) << "\n";
        std::cout << "\tvalue32: 0x" << std::hex << std::setfill('0') << std::setw(8) << static_cast<int>(templateObjectDefinitionSize.value32) << "\n";
      break;

    case TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE:
        templateStructureSize.status = data[i++];
        templateStructureSize.status |= data[i++] << 8;
        templateStructureSize.value32 = data[i++];
        templateStructureSize.value32 |= data[i++] << 8;
        templateStructureSize.value32 |= data[i++] << 16;
        templateStructureSize.value32 |= data[i++] << 24;
        std::cout << "templateStructureSize:\n";
        std::cout << "\tstatus:  0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(templateStructureSize.status) << "\n";
        std::cout << "\tvalue32: 0x" << std::hex << std::setfill('0') << std::setw(8) << static_cast<int>(templateStructureSize.value32) << "\n";
      break;

    default:
      break;
    }
  }

  std::cout << std::endl;
  retData[0] = (templateObjectDefinitionSize.value32 * 4) - 23;//The number of bytes to be read
  retData[1] = templateMemberCount.value16;
  return retData;
}

enum class TagTypeValue : uint16_t {
  BOOL  = 0x00C1,
  SINT  = 0x00C2,
  INT   = 0x00C3,
  DINT  = 0x00C4,
  REAL  = 0x00CA,
  DWORD = 0x00D3,
  LINT  = 0x00C5,
};

std::string getTypecodeString(uint16_t typeCode){
  if (0x8000 & typeCode) {
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

void parseRocwellStructResponse(const std::vector<uint8_t>& data, uint32_t elementsCount) {
  uint16_t arraySize = 0x0000;
  uint16_t typeCode  = 0x0000;
  uint32_t offset = 0x00000000;

  uint32_t i = 0;

  std::cout << "parseRocwellStructResponse\n";

  for (uint32_t j = 0; j < elementsCount; j++)
  {
    arraySize  = data[i++];
    arraySize |= data[i++] << 8;

    typeCode  = data[i++];
    typeCode |= data[i++] << 8;

    offset  = data[i++];
    offset |= data[i++] << 8;
    offset |= data[i++] << 16;
    offset |= data[i++] << 24;

    std::cout << "element " << j << " " << getTypecodeString(typeCode) <<"\n";
    std::cout << "\taraySize: 0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(arraySize) << "\n";
    std::cout << "\ttypeCode: 0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(typeCode) << "\n";
    std::cout << "\toffset:   0x" << std::hex << std::setfill('0') << std::setw(8) << offset << "\n";
    std::cout << std::endl;
  }

}

enum class CalssType : CipUint {
  CONNECTION_MANAGER_CLASS = 0x06,
  SYMBOL_CLASS = 0x6b,
  TEMPLATE_OBJECT = 0x6c,
  ANSI_EXTENDED_SYMBOLIC = 0x91,
};

int main() {
  Logger::setLogLevel(LogLevel::DEBUG);

  start:

#if OS_Windows
  WSADATA wsaData;
  int winsockStart = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (winsockStart != 0) {
    Logger(LogLevel::ERROR) << "Failed to start WinSock - error code: " << winsockStart;
    return EXIT_FAILURE;
  }
#endif

  auto si = std::make_shared<SessionInfo>("192.168.1.100", 0xAF12);

  // Implicit messaging
  auto messageRouter = std::make_shared<MessageRouter>(true);
  ConnectionManager connectionManager(messageRouter);
  IdentityObject identityObject(1, si);

  ConnectionParameters parameters;
  parameters.connectionPath = {0x01, 0x00, 0x20, 0x02, 0x24, 0x01};
  parameters.o2tRealTimeFormat = true;
  parameters.originatorVendorId = 0x051B;
  parameters.originatorSerialNumber = 0xA7347880;
  parameters.t2oNetworkConnectionParams |= NetworkConnectionParams::P2P;
  parameters.t2oNetworkConnectionParams |= NetworkConnectionParams::SCHEDULED_PRIORITY;
  parameters.t2oNetworkConnectionParams |= 10; //size of Assm100 =32
  parameters.t2oNetworkConnectionParams = 0x43f4; //size of Assm100 =32
  parameters.o2tNetworkConnectionParams |= NetworkConnectionParams::P2P;
  parameters.o2tNetworkConnectionParams |= NetworkConnectionParams::SCHEDULED_PRIORITY;
  parameters.o2tNetworkConnectionParams |= 56; //size of Assm150 = 32
  parameters.o2tNetworkConnectionParams = 0x43f4; //size of Assm150 = 32

  parameters.connectionSerialNumber = identityObject.getSerialNumber();
  parameters.o2tRPI = 2000000;
  parameters.t2oRPI = 2000000;
  parameters.transportTypeTrigger = 0xA3;
  parameters.priorityTimeTick = 0x05;
  parameters.timeoutTicks = 0xFF;
  parameters.o2tNetworkConnectionId = 0x00000202;
  parameters.connectionTimeoutMultiplier = 0x02;

  auto io = connectionManager.forwardOpen(si, parameters);

  //считываемые атрибуты
  std::vector<SybolClassAttributeNums> sybolClassAttributes = {
    SybolClassAttributeNums::ATTRIBUTE_TYPE,
    SybolClassAttributeNums::ATTRIBUTE_UNKNOWN_1,
    SybolClassAttributeNums::ATTRIBUTE_UNKNOWN_2,
    SybolClassAttributeNums::ATTRIBUTE_NAME
  };

  uint32_t instaceId = 0x00; //смещение
  //отправка безконектных сообщений сообщения
  //читаем имена программ
  std::vector<ProgrammName> progsName;
  for (;;) {
    auto rockwellMessage = makeRockwellMessage(ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST, EPath((CipUint)CalssType::SYMBOL_CLASS, instaceId), sybolClassAttributes);

    auto response = messageRouter->sendRequest(si, ServiceCodes::READ_TAG_FRAGMENTED, EPath((CipUint)CalssType::CONNECTION_MANAGER_CLASS, 0x01), rockwellMessage);
  
    instaceId = parseRocwellSybolClassResponse(response.getData(), sybolClassAttributes, progsName) + 1;

    if (PARTIAL_TRANSFER != response.getGeneralStatusCode()) {
      break;
    }
  }

  //читаем имена структур
  std::set<StructuresInstace> structuresInstace;
  for (auto progName : progsName) {
    instaceId = 0x00;
    for (;;) {
      auto rockwellMessage = makeRockwellMessage(ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST, EPath((CipUint)CalssType::ANSI_EXTENDED_SYMBOLIC, progName.name, instaceId), sybolClassAttributes);
      auto response = messageRouter->sendRequest(si, ServiceCodes::READ_TAG_FRAGMENTED, EPath((CipUint)CalssType::CONNECTION_MANAGER_CLASS, 0x01), rockwellMessage);
    
      instaceId = parseRocwellSybolClassResponse(response.getData(), sybolClassAttributes, structuresInstace) + 1;

      if (PARTIAL_TRANSFER != response.getGeneralStatusCode()) {
        break;
      }
    }
  }


  instaceId = 0x00;
  // вслучае обрыва соединения надо заново все проинитить
  // для проверки востановления соединения поменять на while (1)
  while (0) {
    auto rockwellMessage = makeRockwellMessage(ServiceCodes::GET_INSTANCE_ATTRIBUTE_LIST, EPath((CipUint)CalssType::ANSI_EXTENDED_SYMBOLIC, progsName[0].name, instaceId), sybolClassAttributes);
    try
    {
      auto response = messageRouter->sendRequest(si, ServiceCodes::READ_TAG_FRAGMENTED, EPath((CipUint)CalssType::CONNECTION_MANAGER_CLASS, 0x01), rockwellMessage);
    }
    catch(...)
    {
      std::cout << "error\n";
      goto start;
    }
    
  }

  //отправка конектных сообщений

  uint16_t sequenceCount = 0x00; // необходимо инкреминтировать для корректной отправкии сообщений
  //запись и чтение данных в тег по имени тега, также можно и по id
  std::cout << "tag string WRITE\n";
  std::string stringTag = "BS502A_S";
  std::vector<uint8_t> elementsToWrite =
  {0xC3, 0x00, 0x01, 0x00, 0x0E, 0x00 };
  // |           |           |
  //TYPE         |           |
  //int 2 bytes  |           |
  //             |           |
  // quantity of elements    |
  //                         |
  //                       value


  if (auto ptr = io.lock()) {
    auto response = sendUnit(si, ServiceCodes::WRITE_TAG, EPath((CipUint)CalssType::ANSI_EXTENDED_SYMBOLIC, std::vector<uint8_t> (stringTag.begin(), stringTag.end()), 0x0000), elementsToWrite, ptr->getO2TNetworkConnectionId(), sequenceCount++);

    for (auto data : response.data) {
      std::cout << "0x" << std::hex << static_cast<int>(data) << " ";
    }

    std::cout << std::endl;
  }

  std::cout << "tag string READ\n";
  stringTag = "BS502A_S";
  std::vector<uint8_t> elementsToRead =
  { 0x01, 0x00 };
  if (auto ptr = io.lock()) {
    auto response = sendUnit(si, ServiceCodes::READ_TAG, EPath((CipUint)CalssType::ANSI_EXTENDED_SYMBOLIC, std::vector<uint8_t> (stringTag.begin(), stringTag.end()), 0x0000), elementsToRead, ptr->getO2TNetworkConnectionId(), sequenceCount++);
    for (auto data : response.data) {
      std::cout << "0x" << std::hex << static_cast<int>(data) << " ";
    }

    std::cout << std::endl;
  }

  std::cout << "READ STRUCTURES\n";


  std::vector<uint8_t> templateObjectPacket {
    0x04, 0x00, // attributes count
    static_cast<uint8_t>(TemplateObjectAttributeNums::ATTRIBUTE_STRUCUTRE_HANDLE),                0x00,
    static_cast<uint8_t>(TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_MEMBER_COUNT),           0x00,
    static_cast<uint8_t>(TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE), 0x00,
    static_cast<uint8_t>(TemplateObjectAttributeNums::ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE),         0x00
  };


  //разбор структур на теги и вложенные структуры
  for (auto &sctructInstance : structuresInstace) {
  std::cout << "READ STRUCTURES1\n";
    if (auto ptr = io.lock()) {
      auto response = sendUnit(si, ServiceCodes::GET_ATTRIBUTE_LIST, EPath((CipUint)CalssType::TEMPLATE_OBJECT, sctructInstance.instance), templateObjectPacket, ptr->getO2TNetworkConnectionId(), sequenceCount++);

      auto parsedData = parseRocwellTemplateObjectResponse(response.data);

      uint32_t readBytes = parsedData[0];
      std::cout << std::endl;
      std::cout << "readBytes = 0x" << std::hex << std::setfill('0') << std::setw(8) << std::hex << readBytes << "\n";
      std::vector<uint8_t> readBytesPack = 
      {
        0x00,0x00,0x00,0x00, //always 0
        static_cast<uint8_t>(readBytes & 0x000000FF),
        static_cast<uint8_t>((readBytes & 0x0000FF00) >> 8)
      };
      
      if (response.status != 0x00) {
        break;
      }

      std::cout << "READ_TAG\n";
      response = sendUnit(si, ServiceCodes::READ_TAG, EPath(0x6C, sctructInstance.instance), readBytesPack, ptr->getO2TNetworkConnectionId(), sequenceCount++);
      //парсим типы и офсеты, также там присутствуют имена тегов, но я не понял как их нормально парсить.
      parseRocwellStructResponse(response.data, parsedData[1]);
    }
  }

  auto count = 10;
  while (connectionManager.hasOpenConnections() && count-- > 0) {
    connectionManager.handleConnections(std::chrono::milliseconds(100));
  }
  connectionManager.forwardClose(si, io);

#if OS_Windows
  WSACleanup();
#endif

  return EXIT_SUCCESS;
}
