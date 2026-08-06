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
WgPrivateKey<TP>::WgPrivateKey() {
    generate();
}

template<typename TP>
WgPrivateKey<TP>::WgPrivateKey(WgPrivateKey<TP>&& other) noexcept {
    if (this != &other) {
        this->key = other.key;
        other.makeZero();
    }
}

template<typename TP>
WgPrivateKey<TP>& WgPrivateKey<TP>::operator=(WgPrivateKey&& other) noexcept {
    if (this != &other) {
        this->key = other.key;
        other.makeZero();
    }

    return *this;
}

template<typename TP>
bool WgPrivateKey<TP>::isProper() const noexcept {
    return this->isGenerated;
}

template<typename TP>
void WgPrivateKey<TP>::generate() {
    typename TP::Lock lock(this->mutex);
    wg_generate_private_key(this->key.data());
    this->isGenerated = true;
}


