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

#include "wgpeer.h"


WgPeer::WgPeer(WgPeer &&other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
    }
}

bool WgPeer::operator==(const WgPeer &other) const noexcept {
    return peer && other.peer && std::memcmp(peer->public_key, other.peer->public_key, WG_KEY_LEN) == 0;
}

WgPeer::WgPeer(Protocol proto) noexcept {
    peer = std::unique_ptr<wg_peer, PeerDeleter>(new (std::nothrow) wg_peer());
    this->proto = proto;
}

WgPeer::WgPeer(WgPublicKey *public_key, WgPresharedKey *preshared_key, Protocol proto) noexcept {
    peer = std::unique_ptr<wg_peer, PeerDeleter>(new (std::nothrow) wg_peer());
    if (peer) {
        if (public_key)
            setKey(*public_key, KeyType::PUBLIC);
        else if (preshared_key)
            setKey(*preshared_key, KeyType::PRESHARED);
    }

    this->proto = proto;
}

void WgPeer::setPublicKey(WgPublicKey &key) const {
    setKey(key, KeyType::PUBLIC);
}

void WgPeer::setPresharedKey(WgPresharedKey &key) const {
    setKey(key, KeyType::PRESHARED);
}

void WgPeer::connectPeer(WgPeer &other) noexcept {
    if (peer == nullptr)
        return;
    peer->next_peer = other.peer.get();
}

void WgPeer::disconnectPeer() noexcept {
    if (peer == nullptr)
        return;
    peer->next_peer = nullptr;
    peer->flags |= WGPEER_REMOVE_ME;
}

void WgPeer::setPersistentKeepAlive(uint16_t time) const noexcept {
    if (peer == nullptr)
        return;
    peer->persistent_keepalive_interval = time;
    peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
}

bool WgPeer::initialize() noexcept {
    if (peer)
        return false;
    peer = std::unique_ptr<wg_peer, PeerDeleter>(new (std::nothrow) wg_peer());
    return peer.get();
}

void WgPeer::setKey(WgKey &key, KeyType type) const {
    if (peer == nullptr)
        return;
    if (!key.isProper())
        throw std::invalid_argument(std::string(type == KeyType::PRESHARED ? "Preshared" : "Public") + " key must be non zero");

    if (type == KeyType::PUBLIC) {
        std::memmove(peer->public_key, key.data(), key.size());
        peer->flags |= WGPEER_HAS_PUBLIC_KEY;
    }
    else if (type == KeyType::PRESHARED) {
        std::memmove(peer->preshared_key, key.data(), key.size());
        peer->flags |= WGPEER_HAS_PRESHARED_KEY;
    }

    key.makeZero();
}

WgPeer& WgPeer::operator=(WgPeer&& other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
    }
    return *this;
}

void WgPeer::PeerDeleter::operator()(wg_peer *peer) const {
    if (peer) {
        wg_allowedip* ip = peer->first_allowedip;
        while (ip) {
            wg_allowedip* next = ip->next_allowedip;
            delete ip;
            ip = next;
        }
        delete peer;
    }
}
