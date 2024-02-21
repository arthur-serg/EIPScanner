//
// Created by flipback on 11/18/19.
//

#ifndef EIPSCANNER_IOCONNECTION_H
#define EIPSCANNER_IOCONNECTION_H

#include "cip/Types.h"
#include "sockets/UDPSocket.h"

#include <SessionInfoIf.h>
#include <cip/EPath.h>
#include <functional>
#include <memory>
#include <vector>

#include <eip/EncapsPacket.h>

namespace eipScanner {
class ConnectionManager;

/**
 * @class IOConnection
 *
 * @brief Implements an implicit EIP connection
 *
 * @sa eipScanner::ConnectionManager
 */

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
	uint8_t service;
	uint8_t reserved;
	uint16_t status;
	std::vector<uint8_t> data;
};

class IOConnection {

	friend class ConnectionManager;
public:
	using ReceiveDataHandle = std::function<void(cip::CipUdint, cip::CipUint, const std::vector<uint8_t>&)>;
	using SendDataHandle = std::function<void(std::vector<uint8_t>&)>;
	using CloseHandle = std::function<void()>;

	using WPtr=std::weak_ptr<IOConnection>;
	using SPtr=std::shared_ptr<IOConnection>;

	eipScanner::MessageUnitResponse
		sendUnit(SessionInfoIf::SPtr si, eipScanner::cip::CipUsint service,
			const eipScanner::cip::EPath& path,
			const std::vector<uint8_t>& data); 
		//field; //to field, increment sendunit, null connect


	/**
	 * Default destructor
	 */
	~IOConnection();

	/**
	 * @brief Sets data to send via the connection each API period
	 *
	 * @note Set only data. The sequence counter and the real time format header are append automatically
	 * @param data the dat to send
	 */
	void setDataToSend(const std::vector<uint8_t>& data);

	/**
	 * @brief Sets a callback to handle received data
	 *
	 * @param handle
	 */
	void setReceiveDataListener(ReceiveDataHandle handle);

        eip::EncapsPacket createSendUnitDataPacket(cip::CipUdint sessionHandle,
                                                   cip::CipUint timeout,
                                                   std::vector<uint8_t> data);
        /**
         * @brief Sets a callback to notify that the connection was closed
         * @param handle
         */
	void setCloseListener(CloseHandle handle);

/**
 * @brief Sets a callback to handle data to send
 *
 * @param handle
 */
void setSendDataListener(SendDataHandle handle);



cip::CipUdint getO2TNetworkConnectionId(); 
	cip::CipUdint geto2tSequenceNumber();


private:
	IOConnection();
	void notifyReceiveData(const std::vector<uint8_t> &data);
	bool notifyTick();

	cip::CipUdint _o2tNetworkConnectionId;
	cip::CipUdint _t2oNetworkConnectionId;
	cip::CipUdint _o2tAPI;
	cip::CipUdint _t2oAPI;

	uint16_t _sequenceCount;

	size_t _o2tDataSize;
	size_t _t2oDataSize;

	bool _o2tFixedSize;
	bool _t2oFixedSize;

	cip::CipUdint _o2tTimer;
	cip::CipUdint _t2o_timer;

	cip::CipUsint _connectionTimeoutMultiplier;
	cip::CipUdint _connectionTimeoutCount;

	cip::CipUdint _o2tSequenceNumber;
	cip::CipUdint _t2oSequenceNumber;
	cip::CipUdint _serialNumber;

	cip::CipUsint _transportTypeTrigger;
	cip::CipBool  _o2tRealTimeFormat;
	cip::CipBool  _t2oRealTimeFormat;
	cip::CipUint  _sequenceValueCount;
	std::vector<uint8_t> _connectionPath;
	cip::CipUint _originatorVendorId;
	cip::CipUdint _originatorSerialNumber;

	std::vector<uint8_t> _outputData;

	sockets::UDPSocket::UPtr _socket;

	ReceiveDataHandle _receiveDataHandle;
	CloseHandle _closeHandle;
	SendDataHandle _sendDataHandle;

	std::chrono::steady_clock::time_point _lastHandleTime;
};
}

#endif  // EIPSCANNER_IOCONNECTION_H
