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

#ifndef WGKEY_H
#define WGKEY_H

#include "wireguard.h"

#include <cstdint>
#include <memory>
#include <array>
#include <cstring>

constexpr uint32_t WG_KEY_LEN = sizeof(wg_key);

enum class KeyType : uint8_t {
    PRESHARED,
    PRIVATE,
    PUBLIC,
};

inline enum wg_device_flags operator|(enum wg_device_flags a, enum wg_device_flags b) {
    return static_cast<wg_device_flags>(
        static_cast<int>(a) | static_cast<int>(b)
    );
}

inline enum wg_device_flags& operator|=(enum wg_device_flags& a, enum wg_device_flags b) {
    a = a | b;
    return a;
}

class WgKey {
public:
    virtual ~WgKey() = default;

    virtual bool isProper() const noexcept = 0;
    virtual void generate() = 0;

    const uint8_t* data() const noexcept;
    uint32_t size() const noexcept;
    std::shared_ptr<std::array<uint8_t, WG_KEY_LEN>> cloneData() const noexcept;
    bool initialize() noexcept;
    void makeZero() noexcept;

protected:
    std::shared_ptr<std::array<uint8_t, WG_KEY_LEN>> key{nullptr};

    bool isGenerated{false};
};

#endif // WGKEY_H
