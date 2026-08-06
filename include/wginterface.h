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

template<typename ThreadPolicy = MultiThreaded>
class WgInterface {
public:
    using WgKeyStringType = wg_key_b64_string;

    enum InterfaceState : uint8_t {
        UNREGISTERED,
        POWEREDOFF,
        POWEREDON
    };

    virtual ~WgInterface() noexcept;

    WgInterface(const WgInterface&) = delete;
    WgInterface& operator=(const WgInterface&) noexcept = delete;

    WgInterface(WgInterface&& other) noexcept;
    WgInterface& operator=(WgInterface&& other) noexcept;

    WgInterface(const std::string& name);
    WgInterface(const char* name);

    bool inline hasDevice() const noexcept;
    bool inline hasPrivateKey() const noexcept;
    bool inline isListening() const noexcept;
    bool inline isSet() const noexcept;

    const char* getName() const noexcept;
    uint16_t getPort() const noexcept;
    uint32_t getFWMark() const noexcept;

    void setListeningPort(uint16_t port) const;
    void setFWMark(uint32_t mark) const noexcept;

    virtual void setName(const std::string& name);
    virtual void setName(const char* name);

    virtual void setPrivateKey(WgPrivateKey<ThreadPolicy>&& private_key, bool force = false);

    // TO DO
    // Change wg_peer with self implemented version later
    virtual void addPeer(WgPeer<ThreadPolicy>&& peer);
    virtual void removePeer(const WgPublicKey<ThreadPolicy>& key);

    virtual void set();
    virtual void release();

    std::vector<std::string> getPeers() const;

protected:
    std::unique_ptr<wg_device> device;
    std::forward_list<std::unique_ptr<WgPeer<ThreadPolicy>>> peers;
    InterfaceState state{UNREGISTERED};

    void setKey(WgKey<ThreadPolicy>&& key, KeyType type, bool force = false);

    mutable typename ThreadPolicy::Mutex mutex;

private:
    inline bool tryValidateName(const char* name) const noexcept;
    void invalidatePeers() noexcept;
    void setNameAbstr(const char* name);
};

#include "wginterface.hpp"

#endif