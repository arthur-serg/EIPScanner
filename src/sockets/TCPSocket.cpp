//
// Created by Aleksey Timin on 11/16/19.
//

#include <system_error>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "utils/Logger.h"
#include "TCPSocket.h"

namespace sockets {
	using eipScanner::utils::Logger;
	using eipScanner::utils::LogLevel;

	TCPSocket::TCPSocket(std::string host, int port, size_t bufferSize)
			: _host{std::move(host)}
			, _port{port}
			, _recvBuffer(bufferSize)
			, _recvTimeout(0){

		_sockedFd = socket(AF_INET, SOCK_STREAM, 0);
		if (_sockedFd < 0) {
			throw std::system_error(errno, std::generic_category());
		}

		Logger(LogLevel::DEBUG) << "Opened socket fd=" << _sockedFd;

		Logger(LogLevel::DEBUG) << "Parsing IP from " << _host;
		struct sockaddr_in addr{};
		if (inet_aton(_host.c_str(), &addr.sin_addr) < 0) {
			close(_sockedFd);
			throw std::system_error(errno, std::generic_category());
		}

		addr.sin_family = AF_INET;
		addr.sin_port = htons(_port);

		Logger(LogLevel::DEBUG) << "Connecting to " << _host << ":" << _port;
		if (connect(_sockedFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			close(_sockedFd);
			throw std::system_error(errno, std::generic_category());
		}
	}

	TCPSocket::~TCPSocket() {
		Logger(LogLevel::DEBUG) << "Close socket fd=" << _sockedFd;
		shutdown(_sockedFd, SHUT_RDWR);
		close(_sockedFd);
	}

	void TCPSocket::Send(const std::vector <uint8_t> &data) const {
		Logger(LogLevel::TRACE) << "Send " << data.size() << " bytes from TCP socket #" << _sockedFd << ".";

		int count = send(_sockedFd, data.data(), data.size(), 0);
		if (count < data.size()) {
			throw std::system_error(errno, std::generic_category());
		}
	}

	std::vector<uint8_t> TCPSocket::Receive(size_t size) {
		int count = 0;
		while (size > count) {
			auto len = recv(_sockedFd, _recvBuffer.data(), size, 0);
			count += len;
			if (len < 0) {
				throw std::system_error(errno, std::generic_category());
			}

			if (len == 0) {
				break;
			}
		}

		if (size != count) {
			Logger(LogLevel::WARNING) << "Received from " << _host << ":" << _port
									  << " " << count << " of " << size;
		}

		std::vector<uint8_t> data(count);
		std::copy(_recvBuffer.data(), _recvBuffer.data() + count, data.begin());

		return data;
	}

	int TCPSocket::getSockedFd() const {
		return _sockedFd;
	}

	const std::string &TCPSocket::getHost() const {
		return _host;
	}

	int TCPSocket::getPort() const {
		return _port;
	}

	const std::chrono::milliseconds &TCPSocket::getRecvTimeout() const {
		return _recvTimeout;
	}

	void TCPSocket::setRecvTimeout(const std::chrono::milliseconds &recvTimeout) {
		_recvTimeout = recvTimeout;

		struct timeval tv = {
				.tv_sec = recvTimeout.count()/1000,
				.tv_usec =  (recvTimeout.count()%1000)*1000
		};
		setsockopt(_sockedFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
	}
}