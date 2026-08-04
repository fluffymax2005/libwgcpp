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

#include <memory>
#include <forward_list>
#include <algorithm>

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
    WgPeer(WgPublicKey* public_key, WgPresharedKey* preshared_key = nullptr);
    WgPeer();

    void setPublicKey(WgPublicKey&& key) const;
    void setPresharedKey(WgPresharedKey&& key) const;

    // TO DO
    // Implement endpoint and integrate there
    void setEndpoint(const wg_endpoint& endpoint) const;

    void connectPeer(wg_peer* other) noexcept;
    void disconnectPeer() noexcept;

    void setPersistentKeepAlive(uint16_t time) const noexcept;

    bool hasPublicKey(const WgPublicKey& key) const noexcept;

    void addAllowedIP(WgAllowedIP&& ip);
    void removeAllowedIP(const std::string& cidr) noexcept;

    wg_peer* getStruct() const noexcept;

private:
    std::unique_ptr<wg_peer> peer;
    std::forward_list<std::unique_ptr<WgAllowedIP>> ips;

    void setKey(WgKey&& key, KeyType type) const;

    void invalidateAllowedIPs() noexcept;

};

#endif // WGPEER_H
