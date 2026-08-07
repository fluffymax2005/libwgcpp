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
 * @brief Provides implementation for Wireguard public key
 */

#ifndef WGPUBLICKEY_H
#define WGPUBLICKEY_H

#include "wgprivatekey.h"
#include "threadsafety.h"

#include <stdexcept>

/**
 * @class WgPublicKey
 * @brief Implementation of Wireguard public key.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgPublicKey : public WgKey<ThreadPolicy> {
public:

    /**
     * @brief Constructs object from private key.
     * @param private_key private key
     * @throw WgException if <TT>private_key.isProper == false</TT>.
     */
    WgPublicKey(WgPrivateKey<ThreadPolicy> private_key);

    /**
     * @brief Default copy constructor. Copies <TT>this->key</TT> from <TT>other.key</TT> and
     * <TT>this->private_key</TT> from <TT>other.private_key.
     */
    WgPublicKey(const WgPublicKey&) noexcept = default;

    /**
     * @brief Default copy assinment. Copies <TT>this->key</TT> from <TT>other.key</TT> and
     * <TT>this->private_key</TT> from <TT>other.private_key.
     * @return *this.
     */
    WgPublicKey& operator=(const WgPublicKey&) noexcept = default;

    /**
     * @brief Move constructor. Copies <TT>this->key</TT> from <TT>other.key</TT> and calls <TT>other.key.makeZero</TT>
     * and copies <TT>this->private_key</TT> from <TT>other.private_key<TT> and calls <TT>other.private_key.makeZero</TT>.
     * @param other other instance
     */
    WgPublicKey(WgPublicKey&& other) noexcept;

    /**
     * @brief Move assignment. Copies <TT>this->key</TT> from <TT>other.key</TT> and calls <TT>other.key.makeZero</TT>
     * and copies <TT>this->private_key</TT> from <TT>other.private_key<TT> and calls <TT>other.private_key.makeZero</TT>.
     * @param other other instance
     */
    WgPublicKey& operator=(WgPublicKey&& other) noexcept;

    /**
     * @brief Check whether key is in valid state.
     * @retval true if <TT>WgPublicKey::isGenerated == true</TT>.
     * @retval false otherwise.
     */
    virtual bool isProper() const noexcept override;

    /**
     * @brief Perform generating WgPublicKey::key
     */
    virtual void generate() override;

private:
    /**
     * @brief Private key generate public key from.
     */
    WgPrivateKey<ThreadPolicy> private_key;
};

#include "wgpublickey.hpp"

#endif // WGPUBLICKEY_H
