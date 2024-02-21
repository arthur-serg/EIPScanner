#pragma once
#include "capi_definition.h"

#ifdef __cplusplus
extern "C"
#endif

{
EIP_API EIP_ErrorCode ConnectDevice(char* hostname, size_t port);

EIP_API EIP_ErrorCode SetLoggerLevel();

EIP_API EIP_ErrorCode MakeRockwellMessage(uint8_t service,const ePath* epath, uint8_t symbolClassAttributes,
    uint8_t* buffer, uint8_t ePathSegmentTypes = 0);

EIP_API EIP_ErrorCode MakeRockwellMessageTagString(uint8_t service, const ePath* epath,
    SymbolClassAttributes symbolClassAttributes,
    uint8_t* buffer, uint8_t ePathSegmentTypes = 0);


#ifdef __cplusplus
}
#endif
