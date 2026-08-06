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

#ifndef WGALLOWEDIP_H
#define WGALLOWEDIP_H

extern "C" {
    #include "wireguard.h"
}

#include "threadsafety.h"
#include "wgexception.h"

#include <cstring>
#include <charconv>

#include <string>
#include <arpa/inet.h>

enum class Protocol : uint8_t {
    IPv4 = AF_INET,
    IPv6 = AF_INET6
};

template<typename ThreadPolicy = MultiThreaded>
class WgAllowedIP {
public:
    ~WgAllowedIP() = default;

    // TO DO
    // Consider allowing copy ctor and assignment
    // Point that ip MUST NOT be changed directly outside of class
    // It it compability to C layer

    // Class owns next elem so restricted to copy itself to prevent unexpected destruction
    WgAllowedIP(const WgAllowedIP& other) noexcept = default;
    WgAllowedIP& operator=(const WgAllowedIP& other) noexcept = default;

    WgAllowedIP(WgAllowedIP&& other) noexcept;
    WgAllowedIP& operator=(WgAllowedIP&& other) noexcept;

    WgAllowedIP() noexcept;
    explicit WgAllowedIP(const std::string& cidr);
    explicit WgAllowedIP(const char* cidr);

    bool operator==(const WgAllowedIP& other) const noexcept;

    void setCIDR(const std::string& cidr);
    void setCIDR(const char* cidr);

    wg_allowedip* getStruct() noexcept;
    void connect(wg_allowedip* other) noexcept;
    void disconnect() noexcept;

    inline Protocol getProto() const noexcept;
    std::string getAddr() const;
    std::string getCIDR() const;
    inline uint8_t getCIDRNumber() const noexcept;

private:
    wg_allowedip ip{};
    mutable typename ThreadPolicy::Mutex mutex;
};

#include "wgallowedip.hpp"

#endif // WGALLOWEDIP_H
