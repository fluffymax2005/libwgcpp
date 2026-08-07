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
 * @brief Provides wg_allowedip struct class wrapper
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

/**
 * @enum
 * @brief The Internet Protocol (IP) versions. POSIX standart values.
 */
enum class Protocol : uint8_t {
    IPv4 = AF_INET, ///< IPv4 (value = 2)
    IPv6 = AF_INET6 ///< IPv6 (value = 10)
};

/**
 * @class WgAllowedIP
 * @brief Wrapper over wg_allowedip struct.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgAllowedIP {
public:

    /**
     * @fn
     * @brief Default destructor
    */
    ~WgAllowedIP() = default;

    /**
     * @brief Default copy constructor
     * @param other other instance of WgAllowedIP
     */
    WgAllowedIP(const WgAllowedIP& other) noexcept = default;

    /**
     * @brief Default copy operator=
     * @param other other instance of WgAllowedIP
     */
    WgAllowedIP& operator=(const WgAllowedIP& other) noexcept = default;

    /**
     * @brief Move constructor
     * @param other other instance of WgAllowedIP
     * @note Copies WgAllowedIP::ip, but sets <TT>other.ip.next_allowedip = nullptr</TT>
     */
    WgAllowedIP(WgAllowedIP&& other) noexcept;

    /**
     * @brief Move operator=
     * @param other other instance of WgAllowedIP
     * @note Sets <TT>other.ip.next_allowedip = nullptr</TT>
     */
    WgAllowedIP& operator=(WgAllowedIP&& other) noexcept;


    /**
     * @brief Default constructor. Initializes WgAllowedIP::ip as if it contains "0.0.0.0/0"
     */
    WgAllowedIP() noexcept;

    /**
     * @brief Constructs object using CIDR. STL version
     * @param cidr CIDR string representation
     * @throws
     * - std::invalid_argument if incorrect IPv4 or IPv6 representation is given <b>OR</b> invalid address index
     * is provided <b>OR</b> prefix is not in range [0; 32] and [0; 128] for IPv4 and IPv6, respectively
     */
    explicit WgAllowedIP(const std::string& cidr);

    /**
     * @brief Constructs object using CIDR. C version
     * @param cidr CIDR string representation
     * @throws
     * - std::invalid_argument if incorrect IPv4 or IPv6 representation is given <b>OR</b> invalid address index
     * is provided <b>OR</b> prefix is not in range [0; 32] and [0; 128] for IPv4 and IPv6, respectively
     */
    explicit WgAllowedIP(const char* cidr);

    /**
     * @brief operator==
     * @param other other instance of WgAllowedIP
     * @return <b>true</b> if this->ip.family == other.ip.family <b>and</b> this->ip.cidr == other.ip.cidr
     * <b>and</b> this->ip.ip4.s_addr == other.ip.ip4.s_addr (for IPv4) or this->ip.ip6 == other.ip.ip6 (for IPv6)<br>
     * <b>false</b> otherwise
     */
    bool operator==(const WgAllowedIP& other) const noexcept;

    /**
     * @brief Changes CIDR of WgAllowedIP::ip. STL version
     * @param cidr CIDR string representation
     * @throws
     * - std::invalid_argument if incorrect IPv4 or IPv6 representation is given <b>OR</b> invalid address index
     * is provided <b>OR</b> prefix is not in range [0; 32] and [0; 128] for IPv4 and IPv6, respectively
     */
    void setCIDR(const std::string& cidr);

    /**
     * @brief Changes CIDR of WgAllowedIP::ip. C version
     * @param cidr CIDR string representation
     * @throws
     * - std::invalid_argument if incorrect IPv4 or IPv6 representation is given <b>OR</b> invalid address index
     * is provided <b>OR</b> prefix is not in range [0; 32] and [0; 128] for IPv4 and IPv6, respectively
     */
    void setCIDR(const char* cidr);

    /**
     * @brief C compability layer to interact with other classes
     * @return WgAllowedIP::ip*
     * @warning Should <b>not</b> be modified manually outside of class. Use only to connect with other classes.
     */
    wg_allowedip* getStruct() noexcept;

    /**
     * @brief Connects this instance with other. If <TT>other == nullptr</TT> does nothing.
     * @param other pointer to other instance
     */
    void connect(wg_allowedip* other) noexcept;

    /**
     * @brief Disconnect this instance. Sets <TT>ip.next_allowedip = nullptr</TT>.
     */
    void disconnect() noexcept;

    /**
     * @brief Casts ip.family to Protocol
     * @return static_cast<Protocol>(ip.family)
     */
    inline Protocol getProto() const noexcept;

    /**
     * @brief Constructs string represantation of address stored by WgAllowedIP::ip. It is always guarantees that address
     * is valid.
     * @return string of address
     * @throw std::bad_alloc if not enough memory to constructs std::string
     */
    std::string getAddr() const;

    /**
     * @brief Constructs string represantation of CIDR stored by WgAllowedIP::ip. It is always garantees that address
     * is valid.
     * @return string of CIDR
     * @throw std::bad_alloc if not enough memory to constructs std::string
     */
    std::string getCIDR() const;

    /**
     * @brief Get CIDR prefix
     * @return WgAllowedIP::ip.cidr
     */
    inline uint8_t getCIDRNumber() const noexcept;

private:

    /**
     * @brief Pure struct. Initialized by default
     */
    wg_allowedip ip{};

    /**
     * @brief Mutex to implement thread safety.
     */
    mutable typename ThreadPolicy::Mutex mutex;
};

#include "wgallowedip.hpp"

#endif // WGALLOWEDIP_H
