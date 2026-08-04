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


#include "wginterface.h"


WgInterface::~WgInterface() noexcept {
    release();
}

WgInterface::WgInterface(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->state = other.state;
        other.state = UNREGISTERED;
        this->peers = std::move(other.peers);
    }
}

WgInterface::WgInterface(const std::string& name) {
    device = std::make_unique<wg_device>();
    setName(name);
}

WgInterface::WgInterface(const char* name) {
    device = std::make_unique<wg_device>();
    setName(name);
}

bool WgInterface::hasDevice() const noexcept {
    return device.get();
}

bool WgInterface::hasPrivateKey() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_PRIVATE_KEY;
    }
    return false;
}

bool WgInterface::isListening() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_LISTEN_PORT && device->listen_port;
    }
    return false;
}

bool WgInterface::isSet() const noexcept {
    return state == POWEREDON;
}

void WgInterface::setListeningPort(uint16_t port) const {
    if (port == 0)
        throw std::invalid_argument("Invalid port for interface \"" + (device ? std::string(device->name) : "") + "\" is given");
    if (device) {
        device->listen_port = port;
        device->flags |= WGDEVICE_HAS_LISTEN_PORT;
    }
}

void WgInterface::setFWMark(uint32_t mark) const noexcept {
    if (device) {
        device->fwmark = mark;
        device->flags |= WGDEVICE_HAS_FWMARK;
    }

}

void WgInterface::setName(const std::string &name) {
    setName(name.c_str());
}

void WgInterface::setName(const char *name) {
    // Setting name is only allowed case interface is powered off and name is valid
    if (device && state == UNREGISTERED && tryValidateName(name)) {

        // Delete device if it existed. Ignore errors
        wg_del_device(name);

        if (wg_add_device(name) < 0)
            throw WgException("Unable to register interface name", errno);
        std::strcpy(device->name, name);
        state = POWEREDOFF;
    }
}

void WgInterface::setPrivateKey(WgPrivateKey&& private_key, bool force) {
    setKey(std::move(private_key), KeyType::PRIVATE, force);
}

void WgInterface::addPeer(WgPeer&& peer) {
    if (peer == nullptr)
        return;
    peers.push_front(std::make_unique<WgPeer>(std::move(peer)));

    // Invalidate peers connections
    invalidatePeers();

    // Apply changes if interface is on
    if (state == POWEREDON) {
        set();
    }
}

void WgInterface::removePeer(const WgPublicKey& key) {
    if (!key.isProper())
        return;
    auto it = std::find_if(peers.begin(), peers.end(), [&key](const std::unique_ptr<WgPeer>& ptr) {
        return ptr->hasPublicKey(key);
    });

    if (it != peers.end()) {
        it->get()->remove();

        auto prev = peers.before_begin();
        while (std::next(prev) != it)
            ++prev;
        peers.erase_after(prev);
        invalidatePeers();
    }
}

void WgInterface::set() {
    if (device) {
        if (wg_set_device(device.get()) < 0)
            throw WgException("Interface \"" + std::string(device->name) + "\" is unable to be set", errno);
        state = POWEREDON;
    }
}

void WgInterface::release() {
    if (device && state != UNREGISTERED) {
        wg_del_device(device->name);
        state = UNREGISTERED;

        device.reset();
        peers.clear();
    }
}

std::vector<std::string> WgInterface::getPeers() const {
    if (device == nullptr)
        return {};

    wg_device* dev;

    if (wg_get_device(&dev, device->name) < 0)
        throw WgException("Unable to get interface", errno);

    std::vector<std::string> peers;
    wg_peer* peer;
    wg_key_b64_string key;
    wg_for_each_peer(dev, peer) {
        wg_key_to_base64(key, peer->public_key);
        try {
            peers.push_back(key);
        } catch (const std::bad_alloc& e) {
            throw WgException(std::string("Unable to get peer's key. Reason: ") + e.what(), ENOMEM);
        }
    }
    wg_free_device(dev);
    return peers;
}

void WgInterface::setKey(WgKey&& key, KeyType type, bool force) {
    if (device == nullptr)
        return;
    if (!force && state == POWEREDON) {
        throw WgException("Interface \"" + std::string(device->name) + "\" is up. Hot key change is not allowed", 1000);
    }

    // Set key anyway
    // Private key request automatically sets public one
    if (type == KeyType::PRIVATE) {
        std::memcpy(device->private_key, key.data(), WG_KEY_LEN);
        device->flags |= WGDEVICE_HAS_PRIVATE_KEY;

        wg_generate_public_key(device->public_key, device->private_key);
        device->flags |= WGDEVICE_HAS_PUBLIC_KEY;

        key.makeZero();
    }
}

bool WgInterface::tryValidateName(const char *name) const noexcept {
    return name && std::strlen(name) > 0 && std::strlen(name) < IFNAMSIZ;
}

void WgInterface::invalidatePeers() const noexcept {
    if (device == nullptr)
        return;


    if (peers.empty()) {
        // Update links case there no peers left
        device->first_peer = nullptr;
        device->last_peer = nullptr;
    } else {
        device->first_peer = peers.front()->getStruct();

        auto first = peers.begin();
        auto second = std::next(first);

        while (second != peers.end()) {
            WgPeer& p1 = *first->get();
            WgPeer& p2 = *second->get();
            p1.connectPeer(p2.getStruct());

            ++first;
            ++second;
        }

        WgPeer& lastPeer = *first->get();
        lastPeer.disconnectPeer();
        device->last_peer = lastPeer.getStruct();
    }

}

WgInterface& WgInterface::operator=(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->state = other.state;
        other.state = UNREGISTERED;
        this->peers = std::move(other.peers);
    }

    return *this;
}


