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
WgPublicKey<TP>::WgPublicKey(WgPrivateKey<TP> private_key)
    : private_key(private_key) {
    generate();
}

template<typename TP>
WgPublicKey<TP>::WgPublicKey(WgPublicKey&& other) noexcept {
    if (this != &other) {
        this->key = other.key;
        private_key = other.private_key;

        other.makeZero();
        other.private_key.makeZero();
    }
}

template<typename TP>
WgPublicKey<TP>& WgPublicKey<TP>::operator=(WgPublicKey&& other) noexcept {
    if (this != &other) {
        this->key = other.key;
        private_key = other.private_key;

        other.makeZero();
        other.private_key.makeZero();
    }

    return *this;
}

template<typename TP>
bool WgPublicKey<TP>::isProper() const noexcept {
    return this->isGenerated;
}

template<typename TP>
void WgPublicKey<TP>::generate() {
    typename TP::Lock lock(this->mutex);
    if (!private_key.isProper())
        throw std::runtime_error("Private key must be nonzero");
    wg_generate_public_key(this->key.data(), private_key.data());
    this->isGenerated = true;
}
