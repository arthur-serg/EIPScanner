//
// Created by Aleksey Timin on 11/16/19.
//

#ifndef EIPSCANNER_CIP_SERVICES_H
#define EIPSCANNER_CIP_SERVICES_H

#include "Types.h"

namespace eipScanner {
namespace cip {

	enum ServiceCodes : CipUsint {
		NONE = 0x00,
		/* Start CIP common services */
		GET_ATTRIBUTE_ALL = 0X01,
		SET_ATTRIBUTE_ALL = 0X02,
		GET_ATTRIBUTE_LIST = 0x03,
		SET_ATTRIBUTE_LIST = 0x04,
		RESET = 0x05,
		START = 0x06,
		STOP = 0x07,
		CREATE_OBJECT_INSTANCE = 0x08,
		DELETE_OBJECT_INSTANCE = 0x09,
		MULTIPLE_SERVICE_PACKET = 0x0A,
		APPLY_ATTRIBUTES = 0x0D,
		GET_ATTRIBUTE_SINGLE = 0X0E,
		SET_ATTRIBUTE_SINGLE = 0X10,
		FIND_NEXT_OBJECT_INSTANCE = 0x11,
		ERROR_RESPONSE = 0x14, //DeviceNet only
		RESTORE = 0x15,
		SAVE = 0x16,
		GET_MEMBER = 0x18,
		NO_OPERATION = 0x17,
		SET_MEMBER = 0x19,
		INSERT_MEMBER = 0x1A,
		REMOVE_MEMBER = 0x1B,
		GROUP_SYNC = 0x1C,

		/* Rockwell Custom Services */
		UNKNOWN_TAG = 0x4B,
		READ_TAG = 0x4C,
		READ_TAG_FRAGMENTED = 0x52,
		WRITE_TAG = 0x4D,
		WRITE_TAG_FRAGMENTED = 0x53,
		READ_MODIFY_WRITE = 0x4E,
		GET_INSTANCE_ATTRIBUTE_LIST = 0x55
		/* End CIP common services */
	};

}
}

#endif //EIPSCANNER_SERVICES_H
