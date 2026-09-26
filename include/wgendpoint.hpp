/*
 * libwgcpp — C++ wrapper for embeddable-wg-library
 * Copyright (C) 2026  Ledovskiy Maksim aka fluffymax2005
 * <santech_montage@mail.ru>
 *
 * This file is part of libwgcpp.
 *
 * libwgcpp is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * libwgcpp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libwgcpp. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * @brief Provides wg_endpoint struct class wrapper
 */

#ifndef WGENDPOINT_H
#define WGENDPOINT_H

extern "C" {
#include "wireguard.h"
}

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdexcept>
#include <string>

#include "threadsafety.hpp"

/**
 * @class WgEndpoint
 * @brief Wrapper over wg_endpoint struct.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 * @note Currently supports **only** IPv4.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgEndpoint {
public:
  /**
   * @brief Copy constructor. Copies this->endpoint from other.endpoint.
   */
  WgEndpoint(const WgEndpoint&) noexcept = default;

  /**
   * @brief Copy assignment. Copies this->endpoint from other.endpoint.
   */
  WgEndpoint& operator=(const WgEndpoint&) noexcept = default;

  /**
   * @brief Move constructor. Copies this->endpoint from other.endpoint.
   */
  WgEndpoint(WgEndpoint&& other) noexcept;

  /**
   * @brief Move assignment. Copies this->endpoint from other.endpoint.
   */
  WgEndpoint& operator=(WgEndpoint&& other) noexcept;

  /**
   * @brief Creates WgEndpoint instance with given ip address and port.
   * @param ip string representation of IP address. IPv4 or IPv6.
   * @param port port number from range [1; 65535]
   * @return created instance
   * @throws
   * - std::invalid_argument if invalid ip address <b>OR</b> port number
   * provided
   */
  static WgEndpoint create(const std::string& ip, uint16_t port);

  /**
   * @brief Validate Endpoint string representation.
   * @param endpoint string representation of endpoint
   * @retval true if valid
   * @retval false otherwise
   */
  static bool validate(const std::string& endpoint);

  /**
   * @brief Get endpoint pure wg_endpoint struct to directly read data
   * @return WgEndpoint::endpoint
   */
  const wg_endpoint& getStruct() const noexcept;

private:
  /**
   * @brief Pure struct.
   */
  wg_endpoint endpoint{};

  /**
   * @brief Mutex to implement thread safety.
   */
  mutable typename ThreadPolicy::Mutex mutex;

  /**
   * @brief Default constructor. Makes WgEndpoint::endpoint as if it contains
   * "0.0.0.0:51820".
   */
  WgEndpoint() noexcept;
};

template<typename TP>
bool WgEndpoint<TP>::validate(const std::string& endpoint) {
  const auto colon_pos = endpoint.find(':');
  if (colon_pos == std::string::npos || colon_pos != endpoint.find_last_of(':'))
	return false;

  std::string_view addr_sv = std::string_view(endpoint).substr(0, colon_pos);
  if (addr_sv.empty() || addr_sv.size() >= INET_ADDRSTRLEN)
	return false;

  in_addr bin_addr;
  if (inet_pton(AF_INET, std::string(addr_sv).c_str(), &bin_addr) != 1)
	return false;

  int port;
  try {
	port = std::stoi(endpoint.substr(colon_pos + 1));
  } catch (...) {
	return false;
  }

  if (port < 0 || port > std::numeric_limits<in_port_t>::max())
	return false;
  return true;
}

template<typename TP>
WgEndpoint<TP>::WgEndpoint() noexcept {
  // Default Wireguard port + phony ip addr
  endpoint.addr4.sin_family = AF_INET;
  endpoint.addr4.sin_port = htons(51820);
}

template<typename TP>
WgEndpoint<TP>::WgEndpoint(WgEndpoint&& other) noexcept {
  if (this != &other) {
	if constexpr (std::is_same_v<TP, MultiThreaded>) {
	  std::lock_guard<std::mutex> lock(other.mutex);

	  this->endpoint = other.endpoint;
	} else {
	  this->endpoint = other.endpoint;
	}
  }
}

template<typename TP>
WgEndpoint<TP>& WgEndpoint<TP>::operator=(WgEndpoint&& other) noexcept {
  if (this != &other) {
	if constexpr (std::is_same_v<TP, MultiThreaded>) {
	  std::scoped_lock lock(this->mutex, other.mutex);

	  this->endpoint = other.endpoint;
	} else {
	  this->endpoint = other.endpoint;
	}
  }

  return *this;
}

template<typename TP>
WgEndpoint<TP> WgEndpoint<TP>::create(const std::string& ip, uint16_t port) {
  WgEndpoint ep;

  if (port == 0)
	throw std::invalid_argument("Port number must be nonzero");

  if (inet_pton(AF_INET, ip.c_str(), &ep.endpoint.addr4.sin_addr) == 1) {
	ep.endpoint.addr4.sin_family = AF_INET;
	ep.endpoint.addr4.sin_port = htons(port);
  } else if (inet_pton(AF_INET6, ip.c_str(), &ep.endpoint.addr6.sin6_addr) == 1) {
	ep.endpoint.addr6.sin6_family = AF_INET6;
	ep.endpoint.addr6.sin6_port = htons(port);
  } else {
	throw std::invalid_argument("Invalid IP: " + ip);
  }

  return ep;
}

template<typename TP>
const wg_endpoint& WgEndpoint<TP>::getStruct() const noexcept {
  typename TP::Lock lock(mutex);
  return endpoint;
}

#endif // WGENDPOINT_H
