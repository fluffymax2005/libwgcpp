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
 * @brief Provides implementation for Wireguard preshared key
 */

#ifndef WGPRESHAREDKEY_H
#define WGPRESHAREDKEY_H

#include "wgkey.h"
#include "threadsafety.h"

/**
 * @class WgPresharedKey
 * @brief Implementation of Wireguard preshared key.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgPresharedKey : public WgKey<ThreadPolicy> {
public:

    /**
     * @brief Default constructor. Calls WgPresharedKey::generate. Key is ready to insert by constructing
     */
    WgPresharedKey() noexcept;

    /**
     * @brief Default copy constructor. Copies <TT>this->key</TT> from <TT>other.key</TT>.
     */
    WgPresharedKey(const WgPresharedKey&) noexcept = default;

    /**
     * @brief Default copy assignment. Copies <TT>this->key</TT> from <TT>other.key</TT>.
     * @return *this.
     */
    WgPresharedKey& operator=(const WgPresharedKey&) noexcept = default;

    /**
     * @brief Move constructor. Copies <TT>this->key</TT> from <TT>other.key</TT> and calls <TT>other.key.makeZero</TT>.
     * @param other other instance
     */
    WgPresharedKey(WgPresharedKey&& other) noexcept;

    /**
     * @brief Move assignment. Copies <TT>this->key</TT> from <TT>other.key</TT> and calls <TT>other.key.makeZero</TT>.
     * @param other other instance
     * @return *this.
     */
    WgPresharedKey& operator=(WgPresharedKey&& other) noexcept;

    /**
     * @brief Check whether key is in valid state.
     * @retval true if <TT>WgPresharedKey::isGenerated == true</TT>.
     * @retval false otherwise.
     */
    virtual bool isProper() const noexcept override;

    /**
     * @brief Perform generating WgPresharedKey::key
     */
    virtual void generate() override;
};

#include "wgpresharedkey.hpp"

#endif // WGPRESHAREDKEY_H
