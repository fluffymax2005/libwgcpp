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
 * @brief Provides implementation for Wireguard private key
 */

#ifndef WGPRIVATEKEY_H
#define WGPRIVATEKEY_H

#include "threadsafety.hpp"
#include "wgkey.hpp"

#include <stdexcept>

/**
 * @class WgPrivateKey
 * @brief Implementation of Wireguard private key.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 */
template <typename ThreadPolicy = MultiThreaded>
class WgPrivateKey : public WgKey<ThreadPolicy> {
public:
  /**
   * @brief Default constructor. Calls WgPrivateKey::generate. Key is ready to
   * insert by constructing
   */
  WgPrivateKey() noexcept;

  /**
   * @brief Constructs object from raw representation of key.
   * @param raw_key raw key representation
   * @throw std::invalid_argument if raw_key is invalid.
   */
  WgPrivateKey(typename WgKey<ThreadPolicy>::key_type raw_key);

  /**
   * @brief Constructs object from Base64 string key representation.
   * @param key Base64 key representation
   * @throw std::invalid_argument if key is invalid.
   * @warning For key validation see WgKey::validateB64StringKey.
   */
  WgPrivateKey(std::string_view key);

  /**
   * @brief Default copy constructor. Copies <TT>this->key</TT> from
   * <TT>other.key</TT>.
   */
  WgPrivateKey(const WgPrivateKey &) noexcept = default;

  /**
   * @brief Default copy assignment. Copies <TT>this->key</TT> from
   * <TT>other.key</TT>.
   * @return *this.
   */
  WgPrivateKey &operator=(const WgPrivateKey &) noexcept = default;

  /**
   * @brief Move constructor. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT>.
   * @param other other instance
   */
  WgPrivateKey(WgPrivateKey &&other) noexcept;

  /**
   * @brief Move assignment. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT>.
   * @param other other instance
   * @return *this.
   */
  WgPrivateKey &operator=(WgPrivateKey &&other) noexcept;

  /**
   * @brief Check whether key is in valid state.
   * @retval true if <TT>WgPrivateKey::isGenerated == true</TT>.
   * @retval false otherwise.
   */
  virtual bool isProper() const noexcept override;

  /**
   * @brief Perform generating WgPrivateKey::key
   */
  virtual void generate() noexcept override;
};

template <typename TP> WgPrivateKey<TP>::WgPrivateKey() noexcept { generate(); }

template <typename TP> WgPrivateKey<TP>::WgPrivateKey(std::string_view key) {
  if (wg_key_from_base64(this->key.data(), key.data()))
    throw std::invalid_argument("Invalid Base64 key provided");
}

template <typename TP>
WgPrivateKey<TP>::WgPrivateKey(typename WgKey<TP>::key_type key) {
  if (wg_key_is_zero(key.data()))
    throw std::invalid_argument("Key must not contain only zero bytes");
  std::memcpy(this->key.data(), key.data(), sizeof(key));
}

template <typename TP>
WgPrivateKey<TP>::WgPrivateKey(WgPrivateKey<TP> &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::lock_guard<std::mutex> lock(other.mutex, std::adopt_lock);

      this->key = other.key;
      other.makeZeroNoMutex();
    } else {
      this->key = other.key;
      other.makeZeroNoMutex();
    }
  }
}

template <typename TP>
WgPrivateKey<TP> &WgPrivateKey<TP>::operator=(WgPrivateKey &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::scoped_lock lock(this->mutex, other.mutex);

      this->key = other.key;
      other.makeZeroNoMutex();
    } else {
      this->key = other.key;
      other.makeZeroNoMutex();
    }
  }

  return *this;
}

template <typename TP> bool WgPrivateKey<TP>::isProper() const noexcept {
  typename TP::Lock lock(this->mutex);
  return !wg_key_is_zero(this->key.data());
}

template <typename TP> void WgPrivateKey<TP>::generate() noexcept {
  typename TP::Lock lock(this->mutex);
  wg_generate_private_key(this->key.data());
}

#endif // WGPRIVATEKEY_H
