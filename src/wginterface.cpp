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
    if (isInterfaceSet)
        release();
}

WgInterface::WgInterface(WgInterface &&other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->isInterfaceSet = other.isInterfaceSet;
        other.isInterfaceSet = false;
    }
}

WgInterface::WgInterface(const std::string &name) noexcept {
    device = std::make_unique<wg_device>();
    if (device == nullptr)
        return;

    setName(name);
}

WgInterface::WgInterface(const char *name) noexcept {
    device = std::make_unique<wg_device>();
    if (device == nullptr)
        return;

    setName(name);
}

bool WgInterface::initialize() noexcept {
    if (device)
        return false;
    device = std::make_unique<wg_device>();
    return device.get();
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
    return isInterfaceSet;
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

void WgInterface::setName(const std::string &name) noexcept {
    setName(name.c_str());
}

void WgInterface::setName(const char *name) noexcept {
    // Setting name is only allowed case interface is powered off and name is valid
    if (device && !isInterfaceSet && tryValidateName(name))
        std::strcpy(device->name, name);
}

void WgInterface::setPrivateKey(WgPrivateKey& private_key, bool force) {
    setKey(private_key, KeyType::PRIVATE, force);
}

void WgInterface::set() noexcept(false) {
    if (isInterfaceSet)
        return;
    // TO DO
    // After WgPeer implementing make this one
}

void WgInterface::release() noexcept(false) {
    poweroff();

    // TO DO
    // Implement WgPeer then manage to free data of peers


    device.release();
}

void WgInterface::poweroff() noexcept(false) {
    if (device && isInterfaceSet) {
        if (wg_del_device(device->name) < 0)
            throw WgException("Interface \"" + std::string(device->name) + "\" is unable to be deleted", errno);
        isInterfaceSet = false;
    }
}

std::vector<std::string> WgInterface::getPeers() const {
    char* device_names;
    char* device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (device_names == nullptr)
        throw WgException("Not enough memory for device names", errno);

    wg_device* device;
    wg_peer* peer;
    wg_key_b64_string key;

    if (wg_get_device(&device, device_name) < 0)
        throw WgException("Unable to get interface", errno);
    std::vector<std::string> peers;
    wg_for_each_peer(device, peer) {
        wg_key_to_base64(key, peer->public_key);
        try {
            peers.push_back(key);
        } catch (const std::bad_alloc& e) {
            throw WgException(std::string("Unable to get peer's key. Reason: ") + e.what(), 0);
        }
    }
    wg_free_device(device);
    return peers;
}

void WgInterface::setKey(WgKey& key, KeyType type, bool force) {
    if (device == nullptr)
        return;
    if (!force && isInterfaceSet) {
        throw WgException("Interface \"" + std::string(device->name) + "\" is up. Hot key change is not allowed", 1000);
    }

    // Set key anyway
    // Private key request automatically set public one
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

WgInterface& WgInterface::operator=(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->isInterfaceSet = other.isInterfaceSet;
        other.isInterfaceSet = false;
    }

    return *this;
}


