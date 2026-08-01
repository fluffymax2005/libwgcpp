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

#include "wgkey.h"

const WgKey::elem_t* WgKey::data() const noexcept {
    return key.data();
}

uint32_t WgKey::size() const noexcept {
    return WG_KEY_LEN;
}

std::array<WgKey::elem_t, WG_KEY_LEN> WgKey::cloneData() const noexcept {
    return key;
}

void WgKey::makeZero() noexcept {
    std::memcpy(key.data(), 0, WG_KEY_LEN);
    isGenerated = false;
}
