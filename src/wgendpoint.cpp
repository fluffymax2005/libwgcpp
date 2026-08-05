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

#include "wgendpoint.h"

WgEndpoint::WgEndpoint() noexcept {
    // Default Wireguard port + phony ip addr
    endpoint.addr4.sin_family = AF_INET;
    endpoint.addr4.sin_port = htons(51820);
}

WgEndpoint WgEndpoint::create(const std::string& ip, uint16_t port) {
    WgEndpoint ep;

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

const wg_endpoint& WgEndpoint::getStruct() const noexcept {
    return endpoint;
}

