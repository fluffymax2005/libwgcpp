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

#include "wgpresharedkey.h"


WgPresharedKey::WgPresharedKey() {
    key = std::make_shared<std::array<uint8_t, WG_KEY_LEN>>();
}

bool WgPresharedKey::isProper() const noexcept {
    return key && isGenerated;
}

void WgPresharedKey::generate() {
    if (key == nullptr)
        return;
    wg_generate_preshared_key(key->data());
    isGenerated = true;
}
