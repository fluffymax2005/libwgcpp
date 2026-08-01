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

#include "wireguard.h"
#include "wgpublickey.h"
#include "wgpresharedkey.h"

#include <memory>

class WgPeer {
public:
    virtual ~WgPeer() noexcept = default;

    // Copying semantics is not allowed
    WgPeer(const WgPeer&) noexcept = delete;
    WgPeer& operator=(const WgPeer&) noexcept = delete;

    WgPeer(WgPeer&& other) noexcept;
    WgPeer& operator=(WgPeer&& other) noexcept;

    // Empty peer if no keys provided
    WgPeer(WgPublicKey* public_key = nullptr, WgPresharedKey* preshared_key = nullptr) noexcept;

    void setPublicKey(WgPublicKey& key) const;
    void setPresharedKey(WgPresharedKey& key) const;

    // TO DO
    // Implement endpoint and integrate there
    void setEndpoint(const wg_endpoint& endpoint) const;

    // TO DO
    // Implement wg_allowedip and integrate there
    void addAllowedIP(const wg_allowedip& allowedip) const;
    void removeAllowedIP(const wg_allowedip allowedip) const;

    void setPersistentKeepAlive(decltype(wg_peer::persistent_keepalive_interval) time) const;

protected:
    // Custom deleter for convenient peer struct destroying
    struct PeerDeleter {
        void operator()(wg_peer* peer) const;
    };

        std::unique_ptr<wg_peer, PeerDeleter> peer{nullptr};
};

#endif // WGPEER_H
