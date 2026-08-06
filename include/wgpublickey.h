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

#ifndef WGPUBLICKEY_H
#define WGPUBLICKEY_H

#include "wgprivatekey.h"
#include "threadsafety.h"

#include <stdexcept>

template<typename ThreadPolicy = MultiThreaded>
class WgPublicKey : public WgKey<ThreadPolicy> {
public:
    WgPublicKey(WgPrivateKey<ThreadPolicy> private_key);

    WgPublicKey(const WgPublicKey&) noexcept = default;
    WgPublicKey& operator=(const WgPublicKey&) noexcept = default;

    WgPublicKey(WgPublicKey&& other) noexcept;
    WgPublicKey& operator=(WgPublicKey&& other) noexcept;


    virtual bool isProper() const noexcept override;
    virtual void generate() override;

private:
    WgPrivateKey<ThreadPolicy> private_key;
};

#include "wgpublickey.hpp"

#endif // WGPUBLICKEY_H
