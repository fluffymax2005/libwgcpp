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


inline enum wg_peer_flags operator|(enum wg_peer_flags a, enum wg_peer_flags b) {
    return static_cast<wg_peer_flags>(
        static_cast<int>(a) | static_cast<int>(b)
        );
}

inline enum wg_peer_flags& operator|=(enum wg_peer_flags& a, enum wg_peer_flags b) {
    a = a | b;
    return a;
}

inline enum wg_peer_flags operator&(enum wg_peer_flags a, enum wg_peer_flags b) {
    return static_cast<wg_peer_flags>(
        static_cast<int>(a) & static_cast<int>(b)
        );
}

inline enum wg_peer_flags& operator&=(enum wg_peer_flags& a, enum wg_peer_flags b) {
    a = a & b;
    return a;
}

inline enum wg_peer_flags operator!(enum wg_peer_flags a) {
    return static_cast<wg_peer_flags>(a);
}

template<typename ThreadPolicy = MultiThreaded>
class WgPeer {
public:
    ~WgPeer() noexcept = default;

    // Copying semantics is not allowed
    WgPeer(const WgPeer&) noexcept = delete;
    WgPeer& operator=(const WgPeer&) noexcept = delete;

    WgPeer(WgPeer&& other) noexcept;
    WgPeer& operator=(WgPeer&& other) noexcept;

    bool operator==(const WgPeer& other) const noexcept;

    // Empty peer if no keys provided
    WgPeer(WgPublicKey<ThreadPolicy>* public_key, WgPresharedKey<ThreadPolicy>* preshared_key = nullptr);
    WgPeer();

    void setPublicKey(WgPublicKey<ThreadPolicy>&& key);
    void setPresharedKey(WgPresharedKey<ThreadPolicy>&& key);

    void setEndpoint(const WgEndpoint<ThreadPolicy>& endpoint);

    void connectPeer(wg_peer* other) noexcept;
    void disconnectPeer() noexcept;
    void remove() noexcept;

    void setPersistentKeepAlive(uint16_t time) const noexcept;

    bool hasPublicKey(const WgPublicKey<ThreadPolicy>& key) const noexcept;

    void addAllowedIP(const WgAllowedIP<ThreadPolicy>& ip);
    void removeAllowedIP(const std::string& cidr) noexcept;

    wg_peer* getStruct() const noexcept;

private:
    std::unique_ptr<wg_peer> peer;
    std::forward_list<std::unique_ptr<WgAllowedIP<ThreadPolicy>>> ips;
    mutable typename ThreadPolicy::Mutex mutex;

    void setKey(WgKey<ThreadPolicy>&& key, KeyType type) const;

    void invalidateAllowedIPs() noexcept;

};

#include "wgpeer.hpp"

#endif // WGPEER_H
