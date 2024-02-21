#include "Device.hpp"

#include <IdentityObject.h>

#include "SessionInfo.h"

#include <cip/connectionManager/NetworkConnectionParams.h>

#include<map>

bool Device::Connect(const std::string& hostname, int port)
{
	if (!hostname.empty())
	{
		eipScanner::SessionInfo a(hostname, port);
		si = std::make_shared<eipScanner::SessionInfo>(hostname, port);

		messageRouter = std::make_shared<eipScanner::MessageRouter>(true);

		const auto connManager = eipScanner::ConnectionManager(messageRouter);

		eipScanner::IdentityObject identityObject(1, si);

		parameters.connectionPath = {0x01, 0x00, 0x20, 0x02, 0x24, 0x01};
		parameters.o2tRealTimeFormat = true;
		parameters.originatorVendorId = 0x051B;
		parameters.originatorSerialNumber = 0xA7347880;
		parameters.t2oNetworkConnectionParams |=
			eipScanner::cip::connectionManager::NetworkConnectionParams::P2P;
		parameters.t2oNetworkConnectionParams |= eipScanner::cip::
			connectionManager::NetworkConnectionParams::SCHEDULED_PRIORITY;
		parameters.t2oNetworkConnectionParams |= 10; // size of Assm100 =32
		parameters.t2oNetworkConnectionParams = 0x43f4; // size of Assm100 =32
		parameters.o2tNetworkConnectionParams |=
			eipScanner::cip::connectionManager::NetworkConnectionParams::P2P;
		parameters.o2tNetworkConnectionParams |= eipScanner::cip::
			connectionManager::NetworkConnectionParams::SCHEDULED_PRIORITY;
		parameters.o2tNetworkConnectionParams |= 56; // size of Assm150 = 32
		parameters.o2tNetworkConnectionParams = 0x43f4; // size of Assm150 = 32

		parameters.connectionSerialNumber = identityObject.getSerialNumber();
		parameters.o2tRPI = 2000000;
		parameters.t2oRPI = 2000000;
		parameters.transportTypeTrigger = 0xA3;
		parameters.priorityTimeTick = 0x05;
		parameters.timeoutTicks = 0xFF;
		parameters.o2tNetworkConnectionId = 0x00000202;
		parameters.connectionTimeoutMultiplier = 0x02;

		connectionManager = connManager;

		io = connectionManager.forwardOpen(si, parameters);
		return true;
	}

	return false;
}
