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

#ifndef WGPEER_H
#define WGPEER_H

extern "C" {
    #include "wireguard.h"
}

#include "wgpublickey.h"
#include "wgpresharedkey.h"
#include "wgallowedip.h"
#include "wgendpoint.h"
#include "threadsafety.h"

#include <memory>
#include <forward_list>
#include <algorithm>
#include <cstring>
#include <stdexcept>

/**
 * @brief operator| for wg_peer_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return result of bitwise or a and b
 */
inline enum wg_peer_flags operator|(enum wg_peer_flags a, enum wg_peer_flags b) {
    return static_cast<wg_peer_flags>(
        static_cast<int>(a) | static_cast<int>(b)
        );
}

/**
 * @brief operator |= for wg_peer_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return reference to a which is result of bitwise or a and b
 */
inline enum wg_peer_flags& operator|=(enum wg_peer_flags& a, enum wg_peer_flags b) {
    a = a | b;
    return a;
}

/**
 * @brief operator& for wg_peer_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return result of bitwise and a and b
 */
inline enum wg_peer_flags operator&(enum wg_peer_flags a, enum wg_peer_flags b) {
    return static_cast<wg_peer_flags>(
        static_cast<int>(a) & static_cast<int>(b)
        );
}

/**
 * @brief operator&= for wg_peer_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return reference to a which is result of bitwise and a and b
 */
inline enum wg_peer_flags& operator&=(enum wg_peer_flags& a, enum wg_peer_flags b) {
    a = a & b;
    return a;
}

/**
 * @brief operator! for wg_peer_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return result of bitwise not a and b
 */
inline enum wg_peer_flags operator!(enum wg_peer_flags a) {
    return !static_cast<wg_peer_flags>(a);
}

/**
 * @class WgPeer
 * @brief Wrapper over wg_peer struct
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgPeer {
public:

    /**
     * @brief Default destructor
     */
    ~WgPeer() noexcept = default;

    /**
     * @brief Copy constructor is deleted. Only one WgPeer may own only one wg_peer and WgAllowedIPs.
     */
    WgPeer(const WgPeer&) noexcept = delete;

    /**
     * @brief Copy assignment is deleted. Only one WgPeer may own only one wg_peer and WgAllowedIPs.
     */
    WgPeer& operator=(const WgPeer&) noexcept = delete;

    /**
     * @brief Move constructor. Move ownership of WgPeer::peer nad WgPeer::ips from <TT>other</TT> to <TT>this</TT>.
     * @param other other instance
     */
    WgPeer(WgPeer&& other) noexcept;

    /**
     * @brief Move assignment. Move ownership of WgPeer::peer nad WgPeer::ips <TT>other</TT> to <TT>this</TT>.
     * @param other other instance
     */
    WgPeer& operator=(WgPeer&& other) noexcept;

    /**
     * @brief Compare to two obects.
     * @param other other instance
     * @retval true if:
     * - <TT>peer == other.peer</TT>;
     * - <TT>peer.public_key equals other.public_key</TT>
     * @retval false otherwise
     */
    bool operator==(const WgPeer& other) const noexcept;

    /**
     * @brief Constructor. Makes instance based of public key and preshared key (optional)
     * @param public_key public key
     * @param preshared_key preshared key (optional)
     * @throw WgException if <TT>public_key->isProper == false</TT> <b>OR</b> <TT>preshared_key->isProper == false</TT>.
     * Implies not nullptr pointers to keys.
     * @note If nullptr provided instead of valid pointer contructor does not in relation to approriate key.
     */
    WgPeer(WgPublicKey<ThreadPolicy>* public_key, WgPresharedKey<ThreadPolicy>* preshared_key = nullptr);

    /**
     * @brief Default contructor.
     * @throw std::bad_alloc by std::make_unique<wg_peer>
     */
    WgPeer();

    /**
     * @brief Set public key. Implies that key may be contained only by one peer.
     * @param key public key
     * @throw WgException if <TT>public_key->isProper == false</TT>.
     */
    void setPublicKey(WgPublicKey<ThreadPolicy>&& key);

    /**
     * @brief Set preshared key. Implies that key may be contained only by one peer.
     * @param key preshared key
     * @throw WgException if <TT>preshared_key->isProper == false</TT>.
     */
    void setPresharedKey(WgPresharedKey<ThreadPolicy>&& key);

    /**
     * @brief Set peer's endpoint
     * @param endpoint instance of endpoint
     */
    void setEndpoint(const WgEndpoint<ThreadPolicy>& endpoint) noexcept;

    /**
     * @brief Connect other peer with current one. C compability layer.
     * @param other
     */
    void connectPeer(wg_peer* other) noexcept;

    /**
     * @brief Disconnect this peer from other one. Effectively calls <TT>peer->next_peer = nullptr</TT>.
     */
    void disconnectPeer() noexcept;

    /**
     * @brief Prepare peer for destruction. Firstly calls WgPeer::disconnectPeer, then set approriate flags
     * to WgPeer::peer->flags.
     */
    void remove() noexcept;

    /**
     * @brief Set persistent keepalive time. Usually 25 is optimal value.
     * @param time time in seconds
     */
    void setPersistentKeepAlive(uint16_t time) const noexcept;

    /**
     * @brief Consider that peer contains key.
     * @param key public key to check
     * @retval true if:
     * - <TT>peer != nullptr;
     * - <TT>peer->public_key equals key.data().
     * @retval false otherwise.
     */
    bool hasPublicKey(const WgPublicKey<ThreadPolicy>& key) const noexcept;

    /**
     * @brief Add AllowedIP.
     * @param ip allowed ip instance
     * @throw std::bad_alloc by std::make_unique<WgAllowedIP<ThreadPolicy>>;
     * @throw std::bad_alloc by std::forward_list::push_front;
     * @note Strong exception guarantee: if an exception is thrown,
     *      the object remains in its original state.
     */
    void addAllowedIP(const WgAllowedIP<ThreadPolicy>& ip);

    /**
     * @brief Remove allowed ip provided by cidr
     * @param cidr CIDR string representation
     * @note If CIDR is invalid method does nothing
     */
    void removeAllowedIP(const std::string& cidr) noexcept;

    /**
     * @brief Get WgPeer::peer raw pointer. C compability layer to interact with other classes.
     * @return WgPeer::peer.get().
     * @warning Should <b>not</b> be modified manually outside of class. Use only to connect with other classes.
     */
    wg_peer* getStruct() const noexcept;

private:
    /**
     * @brief Pointer to wg_peer struct.
     */
    std::unique_ptr<wg_peer> peer;

    /**
     * @brief One-linked list to WgAllowedIP
     */
    std::forward_list<std::unique_ptr<WgAllowedIP<ThreadPolicy>>> ips;

    /**
     * @brief Mutex to implement thread safety.
     */
    mutable typename ThreadPolicy::Mutex mutex;

    /**
     * @brief Set public and preshared (optional) keys. Wrapper method.
     * @param key wireguard based key - WgPublicKey or WgPresharedKey
     * @param type key type
     * @throw WgException if <TT>key.isProper == false</TT>
     * @note Ignore WgPrivateKey.
     */
    void setKey(WgKey<ThreadPolicy>&& key, KeyType type) const;

    /**
     * @brief Invalidates connections of allowed ips after modification
     */
    void invalidateAllowedIPs() noexcept;

};

#include "wgpeer.hpp"

#endif // WGPEER_H
