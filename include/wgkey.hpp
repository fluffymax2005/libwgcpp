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

#include <cstring>

template<typename TP>
const typename WgKey<TP>::elem_t* WgKey<TP>::data() const noexcept {
    return key.data();
}

template<typename TP>
uint32_t WgKey<TP>::size() const noexcept {
    return WG_KEY_LEN;
}

template<typename TP>
std::array<typename WgKey<TP>::elem_t, WG_KEY_LEN> WgKey<TP>::cloneData() const noexcept {
    typename TP::Lock lock(mutex);
    return key;
}

template<typename TP>
void WgKey<TP>::makeZero() noexcept {
    typename TP::Lock lock(mutex);
    std::memset(key.data(), 0, WG_KEY_LEN);
    isGenerated = false;
}