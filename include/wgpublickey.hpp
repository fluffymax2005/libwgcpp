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
 * @brief Provides implementation for Wireguard public key
 */

#ifndef WGPUBLICKEY_H
#define WGPUBLICKEY_H

#include "threadsafety.hpp"
#include "wgprivatekey.hpp"

#include <stdexcept>

/**
 * @class WgPublicKey
 * @brief Implementation of Wireguard public key.
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 */
template <typename ThreadPolicy = MultiThreaded>
class WgPublicKey : public WgKey<ThreadPolicy> {
public:
  /**
   * @brief Constructs object from private key.
   * @param private_key private key
   * @throw WgException if <TT>private_key.isProper == false</TT>.
   */
  WgPublicKey(WgPrivateKey<ThreadPolicy> private_key);

  /**
   * @brief Constructs object from raw representation of key.
   * @param key raw key representation
   * @note Use only to generate instance without purpose to regenerate based on
   * private key. Thus <TT>WgPublicKey::generate()</TT> **always** throws
   * exception.
   * @throw std::invalid_argument if key contains only zero bytes.
   */
  WgPublicKey(typename WgKey<ThreadPolicy>::key_type key);

  /**
   * @brief Constructs object from Base64 string key representation.
   * @param key Base64 key representation
   * @throw std::invalid_argument if key is invalid.
   * @warning For key validation see WgKey::validateB64StringKey.
   */
  WgPublicKey(std::string_view key);

  /*
   * @brief Default copy constructor. Copies <TT>this->key</TT> from
   * <TT>other.key</TT> and <TT>this->private_key</TT> from
   * <TT>other.private_key.
   */
  WgPublicKey(const WgPublicKey &) noexcept = default;

  /**
   * @brief Default copy assinment. Copies <TT>this->key</TT> from
   * <TT>other.key</TT> and <TT>this->private_key</TT> from
   * <TT>other.private_key.
   * @return *this.
   */
  WgPublicKey &operator=(const WgPublicKey &) noexcept = default;

  /**
   * @brief Move constructor. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT> and copies <TT>this->private_key</TT>
   * from <TT>other.private_key<TT> and calls
   * <TT>other.private_key.makeZero</TT>.
   * @param other other instance
   */
  WgPublicKey(WgPublicKey &&other) noexcept;

  /**
   * @brief Move assignment. Copies <TT>this->key</TT> from <TT>other.key</TT>
   * and calls <TT>other.key.makeZero</TT> and copies <TT>this->private_key</TT>
   * from <TT>other.private_key<TT> and calls
   * <TT>other.private_key.makeZero</TT>.
   * @param other other instance
   */
  WgPublicKey &operator=(WgPublicKey &&other) noexcept;

  /**
   * @brief Check whether key is in valid state.
   * @retval true if <TT>WgPublicKey::isGenerated == true</TT>.
   * @retval false otherwise.
   */
  virtual bool isProper() const noexcept override;

  /**
   * @brief Perform generating WgPublicKey::key. If <TT>WgPublicKey::isProper ==
   * false</TT> (for example, instance was moved into another one) then
   * generating new private key and public key based on it is performed.
   */
  virtual void generate() noexcept override;

private:
  /**
   * @brief Private key generate public key from.
   */
  WgPrivateKey<ThreadPolicy> private_key;
};

template <typename TP>
WgPublicKey<TP>::WgPublicKey(typename WgKey<TP>::key_type key) {
  if (wg_key_is_zero(key.data()))
    throw std::invalid_argument("Key must not contain only zero bytes");
  std::memcpy(this->key.data(), key.data(), sizeof(key));
}

template <typename TP> WgPublicKey<TP>::WgPublicKey(std::string_view key) {
  if (wg_key_from_base64(this->key.data(), key.data()))
    throw std::invalid_argument("Invalid Base64 key provided");
}

template <typename TP>
WgPublicKey<TP>::WgPublicKey(WgPrivateKey<TP> private_key)
    : private_key(private_key) {
  generate();
}

template <typename TP>
WgPublicKey<TP>::WgPublicKey(WgPublicKey &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::lock(this->mutex, other.mutex);
      std::lock_guard<std::mutex> lock1(this->mutex, std::adopt_lock);
      std::lock_guard<std::mutex> lock2(other.mutex, std::adopt_lock);

      this->key = other.key;
      private_key = std::move(other.private_key);

      other.makeZero();
      other.private_key.makeZero();
    } else {
      this->key = other.key;
      private_key = std::move(other.private_key);

      other.makeZero();
      other.private_key.makeZero();
    }
  }
}

template <typename TP>
WgPublicKey<TP> &WgPublicKey<TP>::operator=(WgPublicKey &&other) noexcept {
  if (this != &other) {
    if constexpr (std::is_same_v<TP, MultiThreaded>) {
      std::lock(this->mutex, other.mutex);
      std::lock_guard<std::mutex> lock1(this->mutex, std::adopt_lock);
      std::lock_guard<std::mutex> lock2(other.mutex, std::adopt_lock);

      this->key = other.key;
      private_key = std::move(other.private_key);

      other.makeZero();
      other.private_key.makeZero();
    } else {
      this->key = other.key;
      private_key = std::move(other.private_key);

      other.makeZero();
      other.private_key.makeZero();
    }
  }

  return *this;
}

template <typename TP> bool WgPublicKey<TP>::isProper() const noexcept {
  typename TP::Lock lock(this->mutex);
  return !wg_key_is_zero(this->key.data());
}

template <typename TP> void WgPublicKey<TP>::generate() noexcept {
  typename TP::Lock lock(this->mutex);
  private_key.generate();
  wg_generate_public_key(this->key.data(), private_key.data());
}

#endif // WGPUBLICKEY_H
