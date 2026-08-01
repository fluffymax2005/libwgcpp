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

#include "wgpeer.h"


WgPeer::WgPeer(WgPeer &&other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
    }
}

WgPeer::WgPeer(WgPublicKey *public_key, WgPresharedKey *preshared_key) noexcept {
    peer = std::unique_ptr<wg_peer, PeerDeleter>(new (std::nothrow) wg_peer());
    if (peer) {
        if (public_key && !wg_key_is_zero(public_key->data()))
            //peer->public_key = public_key->data();
    }

}

WgPeer& WgPeer::operator=(WgPeer&& other) noexcept {
    if (this != &other) {
        peer = std::move(other.peer);
    }
    return *this;
}



