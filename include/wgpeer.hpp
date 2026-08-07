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

template<typename TP>
WgPeer<TP>::WgPeer(WgPeer&& other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
        ips = std::move(other.ips);
    }
}

template<typename TP>
bool WgPeer<TP>::operator==(const WgPeer& other) const noexcept {
    return peer && other.peer && std::memcmp(peer->public_key, other.peer->public_key, WG_KEY_LEN) == 0;
}

template<typename TP>
WgPeer<TP>::WgPeer()
    : peer{std::make_unique<wg_peer>()} {
}

template<typename TP>
WgPeer<TP>::WgPeer(WgPublicKey<TP>* public_key, WgPresharedKey<TP>* preshared_key) {
    peer = std::make_unique<wg_peer>();
    if (public_key)
        setKey(std::move(*public_key), KeyType::PUBLIC);
    if (preshared_key)
        setKey(std::move(*preshared_key), KeyType::PRESHARED);
}

template<typename TP>
void WgPeer<TP>::setPublicKey(WgPublicKey<TP>&& key) {
    typename TP::Lock lock(mutex);
    setKey(std::move(key), KeyType::PUBLIC);
}

template<typename TP>
void WgPeer<TP>::setPresharedKey(WgPresharedKey<TP>&& key) {
    typename TP::Lock lock(mutex);
    setKey(std::move(key), KeyType::PRESHARED);
}

template<typename TP>
void WgPeer<TP>::setEndpoint(const WgEndpoint<TP>& endpoint) noexcept {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return;
    peer->endpoint = endpoint.getStruct();
}

template<typename TP>
void WgPeer<TP>::connectPeer(wg_peer* other) noexcept {
    typename TP::Lock lock(mutex);
    if (peer == nullptr || other == nullptr)
        return;    
    peer->next_peer = other;
}

template<typename TP>
void WgPeer<TP>::disconnectPeer() noexcept {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return;

    peer->next_peer = nullptr;
}

template<typename TP>
void WgPeer<TP>::remove() noexcept {
    if (peer) {
        disconnectPeer();

        typename TP::Lock lock(mutex);
        peer->flags |= WGPEER_REMOVE_ME;
    }
}

template<typename TP>
void WgPeer<TP>::setPersistentKeepAlive(uint16_t time) const noexcept {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return;

    peer->persistent_keepalive_interval = time;
    peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
}

template<typename TP>
bool WgPeer<TP>::hasPublicKey(const WgPublicKey<TP>& key) const noexcept {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return false;

    return std::memcmp(peer->public_key, key.data(), WG_KEY_LEN) == 0;
}

template<typename TP>
void WgPeer<TP>::removeAllowedIP(const std::string& cidr) noexcept {
    typename TP::Lock lock(mutex);
    ips.remove_if([&cidr](const std::unique_ptr<WgAllowedIP<TP>>& ptr) {
        return ptr->getCIDR() == cidr;
    });

    invalidateAllowedIPs();
}

template<typename TP>
void WgPeer<TP>::addAllowedIP(const WgAllowedIP<TP>& ip) {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return;

    ips.push_front(std::make_unique<WgAllowedIP<TP>>(ip));

    invalidateAllowedIPs();
}

template<typename TP>
wg_peer* WgPeer<TP>::getStruct() const noexcept {
    return peer.get();
}

template<typename TP>
void WgPeer<TP>::setKey(WgKey<TP>&& key, KeyType type) const {
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

template<typename TP>
void WgPeer<TP>::invalidateAllowedIPs() noexcept {
    if (ips.empty())
        return;

    auto first = ips.begin();
    peer->first_allowedip = (*first).get()->getStruct();

    auto second = std::next(first);
    while (second != ips.end()) {
        auto& ip1 = *first->get();
        auto& ip2 = *second->get();

        ip1.connect(ip2.getStruct());

        ++first;
        ++second;
    }

    auto& rip = *first->get();
    peer->last_allowedip = rip.getStruct();
    rip.disconnect();
}

template<typename TP>
WgPeer<TP>& WgPeer<TP>::operator=(WgPeer&& other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
        ips = std::move(other.ips);
    }
    return *this;
}