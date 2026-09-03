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
 * @brief Provides implementation of base Wireguard key
 */

#ifndef WGKEY_H
#define WGKEY_H

extern "C" {
#include "wireguard.h"
}

#include "threadsafety.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>

/**
 * @brief Length of Wireguard key
 */
constexpr uint32_t WG_KEY_LEN = sizeof(wg_key);

/**
 * @brief Key type
 */
enum class KeyType : uint8_t {
  PRESHARED, ///< Preshared key
  PRIVATE,   ///< Private key
  PUBLIC,    ///< Public key
};

/**
 * @brief operator| for wg_device_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return result of bitwise or a and b
 */
inline enum wg_device_flags operator|(enum wg_device_flags a,
                                      enum wg_device_flags b) {
  return static_cast<wg_device_flags>(static_cast<int>(a) |
                                      static_cast<int>(b));
}

/**
 * @brief operator|= for wg_device_flags type
 * @param a left side flag mask
 * @param b right side flag mask
 * @return reference to a which is result of bitwise or a and b
 */
inline enum wg_device_flags &operator|=(enum wg_device_flags &a,
                                        enum wg_device_flags b) {
  a = a | b;
  return a;
}

/**
 * @class WgKey
 * @brief Base Wireguard key class
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 */
template <typename ThreadPolicy = MultiThreaded> class WgKey {
public:
  /**
   * @brief Type of element of key.
   */
  using elem_t = std::remove_extent_t<wg_key>;

  /**
   * @brief Raw representation of Wireguard key
   */
  using key_type = std::array<elem_t, WG_KEY_LEN>;

  /**
   * @brief Base64 Wireguard string key representation
   */
  using b64_key_type = wg_key_b64_string;

  /**
   * @brief Default virtual destructor.
   */
  virtual ~WgKey() noexcept = default;

  /**
   * @brief Checks whether WgKey::key content is valid.
   * @return
   */
  virtual bool isProper() const noexcept = 0;

  /**
   * @brief Generate key.
   */
  virtual void generate() noexcept = 0;

  /**
   * @brief Get raw const pointer to key content.
   * @return
   */
  const elem_t *data() const noexcept;

  /**
   * @brief Get Wireguard key size.
   * @return
   */
  uint32_t size() const noexcept;

  /**
   * @brief Clone WgKey::key
   * @return cloned WgKey::key
   */
  std::array<elem_t, WG_KEY_LEN> cloneData() const noexcept;

  /**
   * @brief Set WgKey::key array to zero. Calls <TT>std::memset(key.data(), 0,
   * WG_KEY_LEN)</TT>
   */
  void makeZero() noexcept;

  /**
   * @brief Validate raw Wireguard key representation.
   * @param raw_key byte based key representation
   * @retval true if valid
   * @retval false otherwise
   */
  static bool validateRawKey(const key_type &raw_key) noexcept;

  /**
   * @brief Validate Base64 string Wireguard key representation.
   * @param key Base64 Wireguard key representation
   * @retval true if valid
   * @retval false otherwise
   * @warning Key **must** be valid null terminated string. Otherwise UB is
   * reached.
   */
  static bool validateB64StringKey(std::string_view key) noexcept;

  /**
   * @brief Equals WgKey::isProper.
   */
  bool operator==(const WgKey &other) const noexcept;

protected:
  /**
   * @brief Array which contains Wireguard key.
   */
  std::array<elem_t, WG_KEY_LEN> key{};

  /**
   * @brief Mutex to implement thread safety.
   */
  mutable typename ThreadPolicy::Mutex mutex;
};

template <typename TP>
bool WgKey<TP>::validateRawKey(const key_type &raw_key) noexcept {
  return !wg_key_is_zero(raw_key.data());
}

template <typename TP>
bool WgKey<TP>::validateB64StringKey(std::string_view key) noexcept {
  key_type raw_key;
  return wg_key_from_base64(raw_key.data(), key.data()) == 0;
}

template <typename TP>
const typename WgKey<TP>::elem_t *WgKey<TP>::data() const noexcept {
  typename TP::Lock lock(mutex);
  return key.data();
}

template <typename TP>
bool WgKey<TP>::operator==(const WgKey &other) const noexcept {
  return isProper();
}

template <typename TP> uint32_t WgKey<TP>::size() const noexcept {
  return WG_KEY_LEN;
}

template <typename TP>
std::array<typename WgKey<TP>::elem_t, WG_KEY_LEN>
WgKey<TP>::cloneData() const noexcept {
  typename TP::Lock lock(mutex);
  return key;
}

template <typename TP> void WgKey<TP>::makeZero() noexcept {
  typename TP::Lock lock(mutex);
  std::memset(key.data(), 0, WG_KEY_LEN);
}

#endif // WGKEY_H
