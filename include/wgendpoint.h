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

#ifndef WGENDPOINT_H
#define WGENDPOINT_H

extern "C" {
    #include "wireguard.h"
}

#include "threadsafety.h"

#include <arpa/inet.h>
#include <string>


template<typename ThreadPolicy = MultiThreaded>
class WgEndpoint {
public:
    WgEndpoint() noexcept;

    // Trivial behaviour for copy ctor and assignment
    WgEndpoint(const WgEndpoint&) noexcept = default;
    WgEndpoint& operator=(const WgEndpoint&) noexcept = default;

    // Trivial behaviour for move ctor and assignment
    WgEndpoint(WgEndpoint&&) noexcept = default;
    WgEndpoint& operator=(WgEndpoint&&) noexcept = default;

    static WgEndpoint create(const std::string& ip, uint16_t port);

    const wg_endpoint& getStruct() const noexcept;

private:
    wg_endpoint endpoint{};
};

#include "wgendpoint.hpp"

#endif // WGENDPOINT_H