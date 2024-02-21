#pragma once
#include <cstdint>
#include <type_traits>

#define EIP_API_C_LIB_EXPORT
#if defined(_WIN32)
#if defined(EIP_API_C_LIB_EXPORT)
#define EIP_API __declspec(dllexport)
#elif defined(EIP_API_C_LIB_IMPORT)
#define EIP_API __declspec(dllimport)
#else
#define EIP_API
#endif
#else
#if defined(EIP_API_C_LIB_EXPORT)
#define EIP_API __attribute__((visibility("default")))
#elif defined(EIP_API_C_LIB_IMPORT)
#define EIP_API
#else
#define EIP_API
#endif
#endif

enum class EIP_ErrorCode : size_t {
  None,
  ConnectionFailed,
  RuntimeError,
};

enum class EIP_LogLevel : size_t {
  OFF = 0,
  ERR,
  WARNING,
  INFO,
  DEBUG,
  TRACE
};

struct ePath
{
	uint16_t classId;
	uint16_t objectId;
	uint16_t attributeId;
	uint16_t size;
	uint8_t* tagString;
	uint64_t tagStringSize;
};

struct SymbolClassAttributes
{
	uint8_t* data;
	uint64_t size;
};