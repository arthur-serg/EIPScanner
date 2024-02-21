#pragma once
#include "ConnectionManager.h"
#include "IOConnection.h"
#include "SessionInfo.h"

class Device {
public:
  Device() = default;

  ~Device() = default;

  bool Connect(const std::string &hostname, int port);

  std::weak_ptr<eipScanner::IOConnection> getIo() { return io; }
  std::shared_ptr<eipScanner::SessionInfo> getSi() { return si; }
  std::shared_ptr<eipScanner::MessageRouter> getMessageRouter() {
    return messageRouter;
  }
  eipScanner::ConnectionManager getConnectionManager() {
    return connectionManager;
  }

private:
  std::shared_ptr<eipScanner::SessionInfo> si{};
  std::weak_ptr<eipScanner::IOConnection> io{};
  std::shared_ptr<eipScanner::MessageRouter> messageRouter{};
  eipScanner::ConnectionManager connectionManager;
  eipScanner::cip::connectionManager::ConnectionParameters parameters{};
  std::string hostname{};
  int port{};
};
