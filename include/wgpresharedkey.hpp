/*
 * libwgcpp — C++ wrapper for embeddable-wg-library
 * Copyright (C) 2026  Ledovskiy Maksim aka fluffymax2005
 * <santech_montage@mail.ru>
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

#include "threadsafety.hpp"
#include "wgkey.hpp"

#include <stdexcept>

/**
 * @class WgPresharedKey
 * @brief Implementation of Wireguard preshared key.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 */
template <typename ThreadPolicy = MultiThreaded>
class WgPresharedKey : public WgKey<ThreadPolicy> {
public:
  /**
   * @brief Default constructor. Calls WgPresharedKey::generate. Key is ready to
   * insert by constructing
   */
  WgPresharedKey() noexcept;

  /**
   * @brief Constructs object from raw representation of key.
   * @param key raw key representation
   * @throw std::invalid_argument if key contains only zero bytes.
   */
  WgPresharedKey(typename WgKey<ThreadPolicy>::key_type key);

  /**
   * @brief Constructs object from Base64 string key representation.
   * @param key Base64 key representation
   * @throw std::invalid_argument if key is invalid.
   * @warning For key validation see WgKey::validateB64StringKey.
   */
  WgPresharedKey(std::string_view key);

  /**
   * @brief Default copy constructor. Copies <TT>this->key</TT> from
   * <TT>other.key</TT>.
   */
  WgPresharedKey(const WgPresharedKey &) noexcept = default;

  /**
   * @brief Default copy assignment. Copies <TT>this->key</TT> from
   * <TT>other.key</TT>.
   * @return *this.
   */
  WgPresharedKey &operator=(const WgPresharedKey &) noexcept = default;

  /**
   * @brief Move constructor. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT>.
   * @param other other instance
   */
  WgPresharedKey(WgPresharedKey &&other) noexcept;

  /**
   * @brief Move assignment. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT>.
   * @param other other instance
   * @return *this.
   */
  WgPresharedKey &operator=(WgPresharedKey &&other) noexcept;

  /**
   * @brief Check whether key is in valid state.
   * @retval true if <TT>WgPresharedKey::isGenerated == true</TT>.
   * @retval false otherwise.
   */
  virtual bool isProper() const noexcept override;

  /**
   * @brief Perform generating WgPresharedKey::key
   */
  virtual void generate() noexcept override;
};

template <typename TP> WgPresharedKey<TP>::WgPresharedKey() noexcept {
  generate();
}

template <typename TP>
WgPresharedKey<TP>::WgPresharedKey(std::string_view key) {
  if (wg_key_from_base64(this->key.data(), key.data()))
    throw std::invalid_argument("Invalid Base64 key provided");
}

template <typename TP>
WgPresharedKey<TP>::WgPresharedKey(typename WgKey<TP>::key_type key) {
  if (wg_key_is_zero(key.data()))
    throw std::invalid_argument("Key must not contain only zero bytes");
  std::memcpy(this->key.data(), key.data(), sizeof(key));
}

template <typename TP>
WgPresharedKey<TP>::WgPresharedKey(WgPresharedKey<TP> &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::lock(this->mutex, other.mutex);
      std::lock_guard<std::mutex> lock1(this->mutex, std::adopt_lock);
      std::lock_guard<std::mutex> lock2(other.mutex, std::adopt_lock);

      this->key = other.key;
      other.makeZero();
    } else {
      this->key = other.key;
      other.makeZero();
    }
  }
}

template <typename TP>
WgPresharedKey<TP> &
WgPresharedKey<TP>::operator=(WgPresharedKey &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::lock(this->mutex, other.mutex);
      std::lock_guard<std::mutex> lock1(this->mutex, std::adopt_lock);
      std::lock_guard<std::mutex> lock2(other.mutex, std::adopt_lock);

      this->key = other.key;
      other.makeZero();
    } else {
      this->key = other.key;
      other.makeZero();
    }
  }

  return *this;
}

template <typename TP> bool WgPresharedKey<TP>::isProper() const noexcept {
  typename TP::Lock lock(this->mutex);
  return !wg_key_is_zero(this->key.data());
}

template <typename TP> void WgPresharedKey<TP>::generate() noexcept {
  typename TP::Lock lock(this->mutex);
  wg_generate_preshared_key(this->key.data());
}

#endif // WGPRESHAREDKEY_H
