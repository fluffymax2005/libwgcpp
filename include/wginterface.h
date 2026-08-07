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
 * @brief Provides wg_device struct class wrapper
*/

#ifndef __WG_INTERFACE__
#define __WG_INTERFACE__


extern "C" {
    #include "wireguard.h"
}

#include "wgpublickey.h"
#include "wgpeer.h"
#include "threadsafety.h"
#include "wgexception.h"

#include <limits>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <string>
#include <cstdint>
#include <memory>
#include <forward_list>
#include <vector>

/**
 * @class WgInterface
 * @brief Wrapper over wg_device struct
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgInterface {
public:

    /**
     * @brief Wireguard key string type
     */
    using WgKeyStringType = wg_key_b64_string;

    /**
     * @brief Interface states
     */
    enum InterfaceState : uint8_t {
        UNREGISTERED, ///< WgInterface::device->name is not registered (wg_device_add) in OS
        POWEREDOFF, ///< WgInterface::device->name is registered (wg_device_add) in OS, but not set (wg_device_set)
        POWEREDON, ///< WgInterface is set (wg_device_set)
    };

    /**
     * @brief Destructor. Releases ownership of resources and deletes interface from OS.
     */
    virtual ~WgInterface() noexcept;


    /**
     * @brief Copy constructor. Delete because only one interface may own resource at a time.
     */
    WgInterface(const WgInterface&) = delete;

    /**
     * @brief Copy assignment. Delete because only one interface may own resource at a time.
     */
    WgInterface& operator=(const WgInterface&) noexcept = delete;

    /**
     * @brief Move constructor. Moves resource management from <TT>other</TT> to <TT>this</TT>.
     */
    WgInterface(WgInterface&& other) noexcept;

    /**
     * @brief Move assignment. Moves resource management from <TT>other</TT> to <TT>this</TT>.
     */
    WgInterface& operator=(WgInterface&& other) noexcept;

    /**
     * @brief Constructs object with given <TT>name</TT>. STL version.
     * @param name string interface name. Must comply with:<br>
     * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
     *   and Linux <linux/if.h>;
     * - Must not be empty;
     * - Allowed characters: [a-zA-Z0-9_\-\.].
     * @throw
     * - WgException with reason and error code. See <linux/socket.h>
     * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
     * @see Linux kernel, <linux/if.h>.
    */
    WgInterface(const std::string& name);

    /**
     * @brief Constructs object with given <TT>name</TT>. C version.
     * @param name string interface name. Must comply with:<br>
     * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
     *   and Linux <linux/if.h>;
     * - Must not be empty;
     * - Allowed characters: [a-zA-Z0-9_\-\.].
     * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
     * @see Linux kernel, <linux/if.h>.
    */
    WgInterface(const char* name);

    /**
     * @brief Consider whether <TT>WgInterface::device != nullptr</TT>.
     * @retval true if <TT>WgInterface::device != nullptr</TT>;
     * @retval false otherwise.
     */
    bool inline hasDevice() const noexcept;

    /**
     * @brief Consider whether valid private key is set.
     * @retval true if:
     * - <TT>WgInterface::hasDevice</TT>;
     * - <TT>device->flags & WGDEVICE_HAS_PRIVATE_KEY != 0</TT>.
     * @retval false otherwise.
     */
    bool inline hasPrivateKey() const noexcept;

    /**
     * @brief Consider whether device is listening. "Listening" means that port is valid and approtiate flag is set.
     * @retval true if:
     * - <TT>WgInterface::hasDevice</TT>;
     * - <TT>device->flags & WGDEVICE_HAS_LISTEN_PORT != 0</TT>.
     * @retval false otherwise.
     */
    bool inline isListening() const noexcept;

    /**
     * @brief Consider whether device is set.
     * @retval true if state == InterfaceState::POWEREDON;
     * @retval false otherwise.
     */
    bool inline isSet() const noexcept;

    /**
     * @brief Get interface's name.
     * @return interface string representation.
     */
    const char* getName() const noexcept;

    /**
     * @brief Get interface's port.
     * @return port number.
     */
    uint16_t getPort() const noexcept;

    /**
     * @brief Get interface's FWMark.
     * @return FWMark.
     */
    uint32_t getFWMark() const noexcept;

    /**
     * @brief Set listening port.
     * @param port number
     * @throw
     * - std::invalid_argument if <TT>port == 0</TT>
     * @note Strong exception guarantee: if an exception is thrown,
     *      the object remains in its original state.
     */
    void setListeningPort(uint16_t port) const;

    /**
     * @brief Set FWMark.
     * @param FWMark
     */
    void setFWMark(uint32_t mark) const noexcept;

    /**
     * @brief Register interface with given name. STL version.
     * @param name string interface name. Must comply with:<br>
     * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
     *   and Linux <linux/if.h>;
     * - Must not be empty;
     * - Allowed characters: [a-zA-Z0-9_\-\.].
     * @throw
     * - WgException with reason and error code. See <linux/socket.h>
     * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
     * @see Linux kernel, <linux/if.h>.
     * @warning WgInterface::state must be equal to InterfaceState::UNREGISTERED. Thus
     * WgInterface::release must be called before this method
     */
    virtual void setName(const std::string& name);

    /**
     * @brief Register interface with given name. STL version.
     * @param name string interface name. Must comply with:<br>
     * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
     *   and Linux <linux/if.h>;
     * - Must not be empty;
     * - Allowed characters: [a-zA-Z0-9_\-\.].
     * @throw
     * - WgException with reason and error code. See <linux/socket.h>
     * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
     * @see Linux kernel, <linux/if.h>.
     * @warning WgInterface::state must be equal to InterfaceState::UNREGISTERED. Thus
     * WgInterface::release must be called before this method
     */
    virtual void setName(const char* name);

    /**
     * @brief Set interface private key.
     * @param private_key private key of interface. Keys should <b>not</b> be kept outside of
     * class by default to prevent leaks so move semantics used.
     * @param force Whether interface should apply changed if it set on. If
     * <TT>WgInterface::state != InterfaceState::POWEREDON</TT> behaves as if <TT>force == false</TT>.
     * @warning <b>Changing</b> interface's private key if some peer are connected to it might lead to connection loss.
     * Use with caution.
     */
    virtual void setPrivateKey(WgPrivateKey<ThreadPolicy>&& private_key, bool force = false);

    /**
     * @brief Add peer into interface
     * @param peer peer to add. Only one interface may own this peer.
     * @throw std::bad_alloc by WgInterface::peers.push_front
     * @throw WgException if <TT>WgInterface::state == InterfaceState::POWEREDON</TT> <b>AND</b> failed to
     *   apply device's changes to kernel
     */
    virtual void addPeer(WgPeer<ThreadPolicy>&& peer);

    /**
     * @brief Remove peer by it's public key.
     * @param key peer's public key
     */
    virtual void removePeer(const WgPublicKey<ThreadPolicy>& key);

    /**
     * @brief Set interface aka wg_set_device.
     * @throw
     * - WgException if setting failed
     * @note Strong exception guarantee: if an exception is thrown,
     *      the object remains in its original state.
     */
    virtual void set();

    /**
     * @brief Release interface resources. Deletes it from kernel as well.
     */
    virtual void release() noexcept;

    /**
     * @brief Get peers public keys.
     * @return array of string representation of peers' public keys
     */
    std::vector<std::string> getPeers() const;

protected:

    /**
     * @brief Pointer to pure wg_device struct.
     */
    std::unique_ptr<wg_device> device;

    /**
     * @brief One-linked list with all peers owned by WgInterface::device.
     */
    std::forward_list<std::unique_ptr<WgPeer<ThreadPolicy>>> peers;

    /**
     * @brief Interface current state.
     */
    InterfaceState state{UNREGISTERED};

    /**
     * @brief Mutex to implement thread safety.
     */
    mutable typename ThreadPolicy::Mutex mutex;

    /**
     * @brief Try validate name according to POSIX standart
     * @param name interface string name
     * @return <b>true</b> if succeed<br>
     * <b>false</b> otherwise
     */
    inline bool tryValidateName(const char* name) const noexcept;

    /**
     * @brief Invalidate WgInterface::peers connection after modifications.
     */
    void invalidatePeers() noexcept;

    /**
     * @brief setNameAbstr
     * @param name. See WgInterface::setName for requirements.
     */
    void setNameAbstr(const char* name);

    /**
     * @brief Set interface's key using abstract key interface
     * @param key key instance
     * @param type type of key
     * @param force whether should permit operation if <TT>WgInterface::state == InterfaceState::POWEREDON</TT>
     * @throw
     * - WgException if <TT>WgInterface::state == InterfaceState::POWEREDON</TT> <b>AND</b> failed to apply
     * device's changes to kernel
     */
    void setKey(WgKey<ThreadPolicy>&& key, KeyType type, bool force = false);
};

template<typename TP>
WgInterface<TP>::~WgInterface() noexcept {
    release();
}

template<typename TP>
WgInterface<TP>::WgInterface(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->state = other.state;
        other.state = UNREGISTERED;
        this->peers = std::move(other.peers);
    }
}

template<typename TP>
WgInterface<TP>::WgInterface(const std::string& name) {
    device = std::make_unique<wg_device>();
    setName(name);
}

template<typename TP>
WgInterface<TP>::WgInterface(const char* name) {
    device = std::make_unique<wg_device>();
    setName(name);
}

template<typename TP>
bool WgInterface<TP>::hasDevice() const noexcept {
    return device.get();
}

template<typename TP>
bool WgInterface<TP>::hasPrivateKey() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_PRIVATE_KEY;
    }
    return false;
}

template<typename TP>
bool WgInterface<TP>::isListening() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_LISTEN_PORT && device->listen_port;
    }
    return false;
}

template<typename TP>
bool WgInterface<TP>::isSet() const noexcept {
    return state == POWEREDON;
}

template<typename TP>
const char* WgInterface<TP>::getName() const noexcept {
    return device ? device->name : nullptr;
}

template<typename TP>
uint16_t WgInterface<TP>::getPort() const noexcept {
    return device ? device->listen_port : 0;
}

template<typename TP>
uint32_t WgInterface<TP>::getFWMark() const noexcept {
    return device ? device->fwmark : std::numeric_limits<uint32_t>::max();
}

template<typename TP>
void WgInterface<TP>::setListeningPort(uint16_t port) const {
    typename TP::Lock lock(mutex);
    if (port == 0)
        throw std::invalid_argument("Invalid port for interface \"" + (device ? std::string(device->name) : "") + "\" is given");
    if (device) {
        device->listen_port = port;
        device->flags |= WGDEVICE_HAS_LISTEN_PORT;
    }
}

template<typename TP>
void WgInterface<TP>::setFWMark(uint32_t mark) const noexcept {
    typename TP::Lock lock(mutex);
    if (device) {
        device->fwmark = mark;
        device->flags |= WGDEVICE_HAS_FWMARK;
    }

}

template<typename TP>
void WgInterface<TP>::setName(const std::string &name) {
    typename TP::Lock lock(mutex);
    setNameAbstr(name.c_str());
}

template<typename TP>
void WgInterface<TP>::setName(const char *name) {
    // Setting name is only allowed case interface is powered off and name is valid
    typename TP::Lock lock(mutex);
    setNameAbstr(name);
}

template<typename TP>
void WgInterface<TP>::setPrivateKey(WgPrivateKey<TP>&& private_key, bool force) {
    setKey(std::move(private_key), KeyType::PRIVATE, force);
}

template<typename TP>
void WgInterface<TP>::addPeer(WgPeer<TP>&& peer) {
    typename TP::Lock lock(mutex);
    if (peer == nullptr)
        return;
    peers.push_front(std::make_unique<WgPeer<TP>>(std::move(peer)));

    // Invalidate peers connections
    invalidatePeers();

    // Apply changes if interface is on
    if (state == POWEREDON) {
        set();
    }
}

template<typename TP>
void WgInterface<TP>::removePeer(const WgPublicKey<TP>& key) {
    typename TP::Lock lock(mutex);
    if (!key.isProper())
        return;
    auto it = std::find_if(peers.begin(), peers.end(), [&key](const std::unique_ptr<WgPeer<TP>>& ptr) {
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

template<typename TP>
void WgInterface<TP>::set() {
    typename TP::Lock lock(mutex);
    if (device) {
        if (wg_set_device(device.get()) < 0)
            throw WgException("Interface \"" + std::string(device->name) + "\" is unable to be set", errno);
        state = POWEREDON;
    }
}

template<typename TP>
void WgInterface<TP>::release() noexcept {
    typename TP::Lock lock(mutex);
    if (device && state != UNREGISTERED) {
        wg_del_device(device->name);
        state = UNREGISTERED;

        device.reset();
    }

    peers.clear();
}

template<typename TP>
std::vector<std::string> WgInterface<TP>::getPeers() const {
    typename TP::Lock lock(mutex);
    if (device == nullptr)
        return {};

    wg_device* dev;

    if (wg_get_device(&dev, device->name) < 0)
        throw WgException("Unable to get interface", errno);

    std::vector<std::string> peers;
    wg_peer* peer;
    WgKeyStringType key;
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

template<typename TP>
void WgInterface<TP>::setKey(WgKey<TP>&& key, KeyType type, bool force) {
    typename TP::Lock lock(mutex);
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

template<typename TP>
bool WgInterface<TP>::tryValidateName(const char* name) const noexcept {
    return name && std::strlen(name) > 0 && std::strlen(name) < IFNAMSIZ;
}

template<typename TP>
void WgInterface<TP>::invalidatePeers() noexcept {
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
            WgPeer<TP>& p1 = *first->get();
            WgPeer<TP>& p2 = *second->get();
            p1.connectPeer(p2.getStruct());

            ++first;
            ++second;
        }

        WgPeer<TP>& lastPeer = *first->get();
        lastPeer.disconnectPeer();
        device->last_peer = lastPeer.getStruct();
    }

}

template<typename ThreadPolicy>
void WgInterface<ThreadPolicy>::setNameAbstr(const char *name) {
    if (device && state == UNREGISTERED && tryValidateName(name)) {
        wg_del_device(name);
        if (wg_add_device(name) < 0)
            throw WgException("Unable to register interface name", errno);
        std::strcpy(device->name, name);
        state = POWEREDOFF;
    }
}

template<typename TP>
WgInterface<TP>& WgInterface<TP>::operator=(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        typename TP::Lock lock(mutex);
        this->device = std::move(other.device);
        this->state = other.state;
        other.state = UNREGISTERED;
        this->peers = std::move(other.peers);
    }

    return *this;
}

#endif