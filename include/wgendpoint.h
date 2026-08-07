/*
 * libwgcpp — C++ wrapper for embeddable-wg-library
 * Copyright (C) 2026  Ledovskiy Maksim aka fluffymax2005 <santech_montage@mail.ru>
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

#include "threadsafety.h"

#include <arpa/inet.h>
#include <string>

/**
 * @class WgEndpoint
 * @brief Wrapper over wg_endpoint struct.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgEndpoint {
public:

    /**
     * @brief Default constructor. Makes WgEndpoint::endpoint as if it contains "0.0.0.0:51820".
     */
    WgEndpoint() noexcept;

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
    WgEndpoint(WgEndpoint&&) noexcept = default;

    /**
     * @brief Move assignment. Copies this->endpoint from other.endpoint.
     */
    WgEndpoint& operator=(WgEndpoint&&) noexcept = default;

    /**
     * @brief Creates WgEndpoint instance with given ip address and port.
     * @param ip string representation of IP address. IPv4 or IPv6.
     * @param port port number from range [1; 65535]
     * @return created instance
     * @throws
     * - std::invalid_argument if invalid ip address <b>OR</b> port number provided
     */
    static WgEndpoint create(const std::string& ip, uint16_t port);

    /**
     * @brief Get endpoint pure wg_endpoint struct to directly read data
     * @return WgEndpoint::endpoint
     */
    const wg_endpoint& getStruct() const noexcept;

private:
    /**
     * @brief Pure struct
     */
    wg_endpoint endpoint{};
};

#include "wgendpoint.hpp"

#endif // WGENDPOINT_H