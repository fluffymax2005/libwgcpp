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
 * @brief Provides wg_device struct class wrapper
 */

#ifndef __WG_INTERFACE__
#define __WG_INTERFACE__

extern "C" {
#include "wireguard.h"
}

#include <linux/netlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <forward_list>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "threadsafety.hpp"
#include "wgexception.h"
#include "wgpeer.hpp"
#include "wgpublickey.hpp"

/**
 * @class WgInterface
 * @brief Wrapper over wg_device struct
 * @tparam ThreadPolicy Thread safety policy for using. MultiThreaded is used by
 * default.
 */
template<typename ThreadPolicy = MultiThreaded>
class WgInterface {
public:
  /**
   * @brief Wireguard key string type
   */
  using WgKeyStringType = wg_key_b64_string;

  /**
   * @brief Interface states
   */
  enum InterfaceState : uint8_t {
	UNREGISTERED, ///< WgInterface::device->name is not registered
	              ///< (wg_device_add) in OS
	POWEREDOFF, ///< WgInterface::device->name is registered (wg_device_add) in
	            ///< OS, but interface is down
	POWEREDON,  ///< WgInterface is up
  };

  /**
   * @brief Destructor. Releases ownership of resources and deletes interface
   * from OS.
   */
  ~WgInterface() noexcept;

  /**
   * @brief Copy constructor. Delete because only one interface may own resource
   * at a time.
   */
  WgInterface(const WgInterface&) = delete;

  /**
   * @brief Copy assignment. Delete because only one interface may own resource
   * at a time.
   */
  WgInterface& operator=(const WgInterface&) noexcept = delete;

  /**
   * @brief Move constructor. Moves resource management from <TT>other</TT> to
   * <TT>this</TT>.
   */
  WgInterface(WgInterface&& other) noexcept;

  /**
   * @brief Move assignment. Moves resource management from <TT>other</TT> to
   * <TT>this</TT>.
   */
  WgInterface& operator=(WgInterface&& other) noexcept;

  /**
   * @brief Default constructor. Instantiate empty interface.
   */
  WgInterface() = default;

  /**
   * @brief Constructs object with given <TT>name</TT>. STL version.
   * @param name string interface name. Must comply with:<br>
   * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
   *   and Linux <linux/if.h>;
   * - Must not be empty;
   * - Allowed characters: [a-zA-Z0-9_\-\.].
   * @throw
   * - WgException if name is ill-formed or interface exists or interface has
   * been already registered.
   * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
   * @see Linux kernel, <linux/if.h>.
   */
  WgInterface(const std::string& name);

  /**
   * @brief Constructs object with given <TT>name</TT>. C version.
   * @param name string interface name. Must comply with:<br>
   * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
   *   and Linux <linux/if.h>;
   * - Must not be empty;
   * - Allowed characters: [a-zA-Z0-9_\-\.].
   * @throw
   * - WgException if name is ill-formed or interface exists or interface has
   * been already registered.
   * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
   * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
   * @see Linux kernel, <linux/if.h>.
   */
  WgInterface(const char* name);

  /**
   * @brief Consider whether <TT>WgInterface::device != nullptr</TT>.
   * @retval true if <TT>WgInterface::device != nullptr</TT>;
   * @retval false otherwise.
   */
  bool inline hasDevice() const noexcept;

  /**
   * @brief Consider whether valid private key is set.
   * @retval true if:
   * - <TT>WgInterface::hasDevice</TT>;
   * - <TT>device->flags & WGDEVICE_HAS_PRIVATE_KEY != 0</TT>.
   * @retval false otherwise.
   */
  bool inline hasPrivateKey() const noexcept;

  /**
   * @brief Consider whether interface has peer with given public key
   * @param key peer's public key to check
   * @retval true if exists.
   * @retval false otherwise.
   */
  bool hasPeerWithPublicKey(const WgPublicKey<ThreadPolicy>& key) const noexcept;

  /**
   * @brief Consider whether interface has peer with given preshared key
   * @param key peer's presahred key to check
   * @retval true if exists.
   * @retval false otherwise.
   */
  bool hasPeerWithPresharedKey(const WgPresharedKey<ThreadPolicy>& key) const noexcept;

  /**
   * @brief Consider whether device is listening. "Listening" means that port is
   * valid and approtiate flag is set.
   * @retval true if:
   * - <TT>WgInterface::hasDevice</TT>;
   * - <TT>device->flags & WGDEVICE_HAS_LISTEN_PORT != 0</TT>.
   * @retval false otherwise.
   */
  bool inline isListening() const noexcept;

  /**
   * @brief Consider whether device is set.
   * @retval true if state == InterfaceState::POWEREDON;
   * @retval false otherwise.
   */
  bool inline isSet() const noexcept;

  /**
   * @brief Consider whether divice is up.
   * @retval true if set up
   * @retval false otherwise.
   */
  bool inline isUp() const noexcept;

  /**
   * @brief Get interface's name.
   * @return interface string representation.
   */
  const char* getName() const noexcept;

  /**
   * @brief Get interface's port.
   * @return port number.
   */
  uint16_t getPort() const;

  /**
   * @brief Get interface's FWMark.
   * @return FWMark.
   */
  uint32_t getFWMark() const noexcept;

  /**
   * @brief Get interface's public key.
   * @return public key new instance if <TT>WgInterface::hasPrivateKey ==
   * true</TT>. Does not remove current one from interface.
   */
  std::optional<WgPublicKey<ThreadPolicy>> getPublicKey() const noexcept;

  /**
   * @brief Get interface's private key.
   * @return private key new instance if <TT>WgInterface::hasPrivateKey ==
   * true</TT>. Does not remove current one from interface.
   * @warning Get private key only in case if you know what you do as
   * unathorized persons must **not** know it. Therioretically it should not
   * leak from interface but there might some cases it's forced risk.
   */
  std::optional<WgPrivateKey<ThreadPolicy>> getPrivateKey() const noexcept;

  /**
   * @brief Set listening port.
   * @param port number
   */
  void setListenPort(uint16_t port) noexcept;

  /**
   * @brief Set FWMark.
   * @param FWMark
   */
  void setFWMark(uint32_t mark) noexcept;

  /**
   * @brief Register interface with given name. STL version.
   * @param name string interface name. Must comply with:<br>
   * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
   *   and Linux <linux/if.h>;
   * - Must not be empty;
   * - Allowed characters: [a-zA-Z0-9_\-\.].
   * @throw
   * - WgException if name is ill-formed or interface exists or interface has
   * been already registered.
   * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
   * @see Linux kernel, <linux/if.h>.
   * @warning WgInterface::state must be equal to InterfaceState::UNREGISTERED.
   * Otherwise, an attempt to change the name will throw a WgException.
   */
  void setName(const std::string& name);

  /**
   * @brief Register interface with given name. STL version.
   * @param name string interface name. Must comply with:<br>
   * - Maximum length: IFNAMSIZ - 1 (15 characters), see IEEE Std 1003.1-2017
   *   and Linux <linux/if.h>;
   * - Must not be empty;
   * - Allowed characters: [a-zA-Z0-9_\-\.].
   * @throw
   * - WgException if name is ill-formed or interface exists or interface has
   * been already registered.
   * @see IEEE Std 1003.1-2017, <sys/socket.h>, IFNAMESIZ.
   * @see Linux kernel, <linux/if.h>.
   * @warning WgInterface::state must be equal to InterfaceState::UNREGISTERED.
   * Otherwise, an attempt to change the name will throw a WgException.
   */
  void setName(const char* name);

  /**
   * @brief Set interface private key.
   * @param private_key private key of interface. Keys should <b>not</b> be kept
   * outside of class by default to prevent leaks so move semantics used.
   * @param force Whether interface should apply changed if it set on. If
   * <TT>WgInterface::state != InterfaceState::POWEREDON</TT> behaves as if
   * <TT>force == false</TT>.
   * @throw WgException if <TT>WgInterface::isSet == true</TT> and <TT>force ==
   * false</TT>
   * @note Sets public key for instance based on given private_key
   * @warning <b>Changing</b> interface's private key if some peer are connected
   * to it might lead to connection loss. Use with caution.
   */
  void setPrivateKey(WgPrivateKey<ThreadPolicy>&& private_key, bool force = false);

  /**
   * @brief Add peer into interface
   * @param peer peer to add. Only one interface may own this peer.
   * @throw std::bad_alloc by WgInterface::peers.push_front
   * @throw WgException if <TT>WgInterface::state ==
   * InterfaceState::POWEREDON</TT> <b>AND</b> failed to apply device's changes
   * to kernel
   */
  void addPeer(WgPeer<ThreadPolicy>&& peer);

  /**
   * @brief Remove peer by it's public key.
   * @param key peer's public key
   */
  void removePeer(const WgPublicKey<ThreadPolicy>& key);

  /**
   * @brief Rotate peer's public key with hot reload.
   * @param old_key peer's current public key
   * @param new_key peer's new public key
   * @throw WgException if either peer not found or runtime error occured
   * applying changes if <TT>WgInterface::isUp == true</TT>/
   */
  void rotatePeersPublicKey(const WgPublicKey<ThreadPolicy>& old_key,
                            WgPublicKey<ThreadPolicy>&& new_key);

  /**
   * @brief Rotate peer's preshared key with hot reload.
   * @param public_key peer's public key
   * @param preshared_key peer's new preshared key
   * @throw WgException if either peer not found or runtime error occured
   * applying changes if <TT>WgInterface::isUp == true</TT>/
   */
  void rotatePeersPresharedKey(const WgPublicKey<ThreadPolicy>& public_key,
                               WgPresharedKey<ThreadPolicy>&& preshared_key);

  /**
   * @brief Change peer's persistent keepalive.
   * @param public_key peer's public key
   * @param time time in seconds
   * @throw std::invalid_argument if time not in range [1; 65535]
   */
  void setPeerPersistentKeepalive(const WgPublicKey<ThreadPolicy>& public_key, uint16_t time);

  /**
   * @brief Set peer's endpoint.
   * @param key peer's public key
   * @param endpoint endpoint instance to install
   * @throw WgException if peer does not exist
   */
  template<typename EndpointArg, typename = std::enable_if_t<std::is_same_v<
                                     std::decay_t<EndpointArg>, WgEndpoint<ThreadPolicy>>>>
  void setPeerEndpoint(const WgPublicKey<ThreadPolicy>& key, EndpointArg&& endpoint);

  /**
   * @brief Add allowed ip for peer.
   * @param key peer's public key
   * @param allowed_ip allowed ip instance to install
   * @throw WgException if peer does not exist
   */
  template<typename AllowedIpArg, typename = std::enable_if_t<std::is_same_v<
                                      std::decay_t<AllowedIpArg>, WgAllowedIP<ThreadPolicy>>>>
  void addPeerAllowedIp(const WgPublicKey<ThreadPolicy>& key, AllowedIpArg&& allowed_ip);

  /**
   * @brief Remove allowed ip from peer.
   * @param key peer's public key
   * @param allowed_ip allowed ip instance to remove
   * @throw WgException if peer does not exist
   */
  template<typename AllowedIpArg, typename = std::enable_if_t<std::is_same_v<
                                      std::decay_t<AllowedIpArg>, WgAllowedIP<ThreadPolicy>>>>
  void removePeerAllowedIp(const WgPublicKey<ThreadPolicy>& key, AllowedIpArg&& allowed_ip);

  /**
   * @brief Set interface aka wg_set_device.
   * @throw WgException if setting failed.
   */
  void set();

  /**
   * @brief Release interface resources. Deletes it from kernel as well.
   */
  void release() noexcept;

  /**
   * @brief Bring up interface.
   * @throw WgException if bringing up failed.
   */
  void bringUp();

  /**
   * @brief Bring down interface.
   * @throw WgException if bringing down failed.
   */
  void bringDown();

private:
  /**
   * @brief Pointer to pure wg_device struct.
   */
  std::unique_ptr<wg_device> device;

  /**
   * @brief One-linked list with all peers owned by WgInterface::device.
   */
  std::forward_list<std::shared_ptr<WgPeer<ThreadPolicy>>> peers;

  /**
   * @brief Interface current state.
   */
  InterfaceState state{UNREGISTERED};

  /**
   * @brief Mutex to implement thread safety.
   */
  mutable typename ThreadPolicy::Mutex mutex;

  /**
   * @brief Try validate name according to POSIX standart
   * @param name interface string name
   * @return <b>true</b> if succeed<br>
   * <b>false</b> otherwise
   */
  inline bool tryValidateName(const char* name) const noexcept;

  /**
   * @brief Invalidate WgInterface::peers connection after modifications.
   */
  void invalidatePeers() noexcept;

  /**
   * @brief setNameAbstr.
   * @param name. See WgInterface::setName for requirements.
   * @see WgException::setName for exceptions.
   */
  void setNameAbstr(const char* name);

  /**
   * @brief Set interface's key using abstract key interface
   * @param key key instance
   * @param type type of key
   * @param force whether should permit operation if <TT>WgInterface::state ==
   * InterfaceState::POWEREDON</TT>
   * @throw
   * - WgException if <TT>WgInterface::state == InterfaceState::POWEREDON</TT>
   * <b>AND</b> failed to apply device's changes to kernel
   */
  void setKey(WgKey<ThreadPolicy>&& key, KeyType type, bool force = false);

  /**
   * @brief Check whether interface with name exists.
   * @param name interface name.
   * @retval true if exists.
   * @retval false otherwise.
   */
  bool interfaceExists(const char name[]) const noexcept;

  /**
   * @brief Wrapper function to bring up or down interface.
   */
  void bringAbstr(bool up);

  /**
   * @brief Set interface without mutex.
   * @see WgInterface::set for exceptions.
   */
  void setNoLock();
};

template<typename TP>
void WgInterface<TP>::setPeerPersistentKeepalive(const WgPublicKey<TP>& public_key, uint16_t time) {
  typename TP::Lock lock(mutex);
  auto it = std::find_if(peers.begin(), peers.end(),
                         [&](const auto& ptr) { return ptr->hasPublicKey(public_key); });
  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  (*it)->setPersistentKeepAlive(time);

  if (state != UNREGISTERED)
	setNoLock();
}

template<typename TP>
void WgInterface<TP>::rotatePeersPublicKey(const WgPublicKey<TP>& old_key,
                                           WgPublicKey<TP>&& new_key) {
  typename TP::Lock lock(mutex);

  auto it = std::find_if(peers.begin(), peers.end(),
                         [&](const auto& ptr) { return ptr->hasPublicKey(old_key); });
  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  (*it)->setPublicKey(std::move(new_key));

  if (state != UNREGISTERED)
	setNoLock();
}

template<typename TP>
void WgInterface<TP>::rotatePeersPresharedKey(const WgPublicKey<TP>& public_key,
                                              WgPresharedKey<TP>&& preshared_key) {
  typename TP::Lock lock(mutex);

  auto it = std::find_if(peers.begin(), peers.end(),
                         [&](const auto& ptr) { return ptr->hasPublicKey(public_key); });
  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  (*it)->setPresharedKey(std::move(preshared_key));

  if (state != UNREGISTERED)
	setNoLock();
}

template<typename TP>
template<typename EndpointArg, typename>
void WgInterface<TP>::setPeerEndpoint(const WgPublicKey<TP>& key, EndpointArg&& endpoint) {
  typename TP::Lock lock(mutex);

  auto it = std::find_if(peers.begin(), peers.end(),
                         [&key](const auto& ptr) { return ptr->hasPublicKey(key); });

  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  it->get()->setEndpoint(std::forward<EndpointArg>(endpoint));

  if (state != UNREGISTERED) {
	setNoLock();
  }
}

template<typename TP>
template<typename AllowedIpArg, typename>
void WgInterface<TP>::addPeerAllowedIp(const WgPublicKey<TP>& key, AllowedIpArg&& allowed_ip) {
  typename TP::Lock lock(mutex);

  auto it = std::find_if(peers.begin(), peers.end(),
                         [&key](const auto& ptr) { return ptr->hasPublicKey(key); });

  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  it->get()->addAllowedIP(std::forward<AllowedIpArg>(allowed_ip));

  if (state != UNREGISTERED) {
	setNoLock();
  }
}

template<typename TP>
template<typename AllowedIpArg, typename>
void WgInterface<TP>::removePeerAllowedIp(const WgPublicKey<TP>& key, AllowedIpArg&& allowed_ip) {
  typename TP::Lock lock(mutex);

  auto it = std::find_if(peers.begin(), peers.end(),
                         [&key](const auto& ptr) { return ptr->hasPublicKey(key); });
  if (it == peers.end())
	throw WgException("Peer not found", ENOENT);

  it->get()->removeAllowedIP(std::forward<AllowedIpArg>(allowed_ip));

  if (state != UNREGISTERED) {
	setNoLock();
  }
}

template<typename TP>
bool WgInterface<TP>::interfaceExists(const char name[]) const noexcept {
  const auto sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
	return false;

  struct ifreq ifr{};
  std::strncpy(ifr.ifr_ifrn.ifrn_name, name, IFNAMSIZ);

  const bool exists = ioctl(sock, SIOCGIFFLAGS, &ifr) == 0;
  close(sock);
  return exists;
}

template<typename TP>
bool WgInterface<TP>::isUp() const noexcept {
  return state == InterfaceState::POWEREDON;
}

template<typename TP>
WgInterface<TP>::~WgInterface() noexcept {
  release();
}

template<typename TP>
std::optional<WgPublicKey<TP>> WgInterface<TP>::getPublicKey() const noexcept {
  typename TP::Lock lock(mutex);
  if (device == nullptr || !(device->flags & WGDEVICE_HAS_PRIVATE_KEY))
	return std::nullopt;

  typename WgKey<TP>::key_type key_data;
  std::memcpy(key_data.data(), device->public_key, sizeof(device->public_key));
  return WgPublicKey<TP>{key_data};
}

template<typename TP>
std::optional<WgPrivateKey<TP>> WgInterface<TP>::getPrivateKey() const noexcept {
  typename TP::Lock lock(mutex);
  if (device == nullptr || !(device->flags & WGDEVICE_HAS_PRIVATE_KEY))
	return std::nullopt;

  typename WgKey<TP>::key_type key_data;
  std::memcpy(key_data.data(), device->private_key, sizeof(device->private_key));
  return WgPrivateKey<TP>{key_data};
}

template<typename TP>
bool WgInterface<TP>::hasPeerWithPublicKey(const WgPublicKey<TP>& key) const noexcept {
  typename TP::Lock lock(mutex);
  auto it = std::find_if(peers.cbegin(), peers.cend(),
                         [&key](const auto& peer) { return peer->hasPublicKey(key); });
  return it != peers.cend();
}

template<typename TP>
bool WgInterface<TP>::hasPeerWithPresharedKey(const WgPresharedKey<TP>& key) const noexcept {
  typename TP::Lock lock(mutex);
  auto it = std::find_if(peers.cbegin(), peers.cend(),
                         [&key](const auto& peer) { return peer->hasPresharedKey(key); });
  return it != peers.cend();
}

template<typename TP>
WgInterface<TP>::WgInterface(WgInterface&& other) noexcept {
  if (this != &other) {
	release();

	if constexpr (std::is_same_v<TP, MultiThreaded>) {
	  std::lock_guard<std::mutex> lock(other.mutex, std::adopt_lock);

	  this->device = std::move(other.device);
	  this->state = other.state;
	  other.state = UNREGISTERED;
	  this->peers = std::move(other.peers);

	} else {
	  this->device = std::move(other.device);
	  this->state = other.state;
	  other.state = UNREGISTERED;
	  this->peers = std::move(other.peers);
	}
  }
}

template<typename TP>
WgInterface<TP>::WgInterface(const std::string& name) {
  device = std::make_unique<wg_device>();
  setName(name);
}

template<typename TP>
WgInterface<TP>::WgInterface(const char* name) {
  device = std::make_unique<wg_device>();
  setName(name);
}

template<typename TP>
bool WgInterface<TP>::hasDevice() const noexcept {
  typename TP::Lock lock(mutex);
  return device.get();
}

template<typename TP>
bool WgInterface<TP>::hasPrivateKey() const noexcept {
  typename TP::Lock lock(mutex);
  if (device) {
	return device->flags & WGDEVICE_HAS_PRIVATE_KEY;
  }
  return false;
}

template<typename TP>
bool WgInterface<TP>::isListening() const noexcept {
  typename TP::Lock lock(mutex);
  if (device) {
	return device->flags & WGDEVICE_HAS_LISTEN_PORT && device->listen_port;
  }
  return false;
}

template<typename TP>
bool WgInterface<TP>::isSet() const noexcept {
  typename TP::Lock lock(mutex);
  return state == POWEREDON;
}

template<typename TP>
const char* WgInterface<TP>::getName() const noexcept {
  typename TP::Lock lock(mutex);
  return device ? device->name : nullptr;
}

template<typename TP>
uint16_t WgInterface<TP>::getPort() const {
  uint16_t port;
  typename TP::Lock lock(mutex);
  if (state == UNREGISTERED) {
	if (device)
	  port = device->listen_port;
	else
	  throw std::runtime_error("Interface is not present. Create new one");
  } else {
	if (device->listen_port)
	  port = device->listen_port;
	else {
	  wg_device* dev;
	  if (wg_get_device(&dev, device->name))
		throw std::runtime_error("Failed to access to kernel for port information");
	  port = dev->listen_port;
	  wg_free_device(dev);
	}
  }

  return port;
}

template<typename TP>
uint32_t WgInterface<TP>::getFWMark() const noexcept {
  typename TP::Lock lock(mutex);
  return device ? device->fwmark : std::numeric_limits<decltype(wg_device::fwmark)>::max();
}

template<typename TP>
void WgInterface<TP>::setListenPort(uint16_t port) noexcept {
  typename TP::Lock lock(mutex);
  if (device) {
	device->listen_port = port;
	device->flags |= WGDEVICE_HAS_LISTEN_PORT;
  }
}

template<typename TP>
void WgInterface<TP>::setFWMark(uint32_t mark) noexcept {
  typename TP::Lock lock(mutex);
  if (device) {
	device->fwmark = mark;
	device->flags |= WGDEVICE_HAS_FWMARK;
  }
}

template<typename TP>
void WgInterface<TP>::setName(const std::string& name) {
  typename TP::Lock lock(mutex);
  setNameAbstr(name.c_str());
}

template<typename TP>
void WgInterface<TP>::setName(const char* name) {
  // Setting name is only allowed case interface is powered off and name is
  // valid
  typename TP::Lock lock(mutex);
  setNameAbstr(name);
}

template<typename TP>
void WgInterface<TP>::setPrivateKey(WgPrivateKey<TP>&& private_key, bool force) {
  setKey(std::move(private_key), KeyType::PRIVATE, force);
}

template<typename TP>
void WgInterface<TP>::addPeer(WgPeer<TP>&& peer) {
  typename TP::Lock lock(mutex);
  peers.push_front(std::make_shared<WgPeer<TP>>(std::move(peer)));

  // Invalidate peers connections
  invalidatePeers();

  // Apply changes if interface is on
  if (state != UNREGISTERED) {
	setNoLock();
  }
}

template<typename TP>
void WgInterface<TP>::removePeer(const WgPublicKey<TP>& key) {
  if (!key.isProper())
	return;

  typename TP::Lock lock(mutex);
  auto it = std::find_if(peers.begin(), peers.end(),
                         [&key](const auto& ptr) { return ptr->hasPublicKey(key); });

  if (it != peers.end()) {
	it->get()->remove();

	auto prev = peers.before_begin();
	while (std::next(prev) != it)
	  ++prev;
	peers.erase_after(prev);
	invalidatePeers();

	if (state != UNREGISTERED)
	  setNoLock();
  }
}

template<typename TP>
void WgInterface<TP>::set() {
  typename TP::Lock lock(mutex);
  setNoLock();
}

template<typename TP>
void WgInterface<TP>::setNoLock() {
  if (device == nullptr)
	return;

  if (state == UNREGISTERED)
	throw WgException("Interface is not registered", EINVAL);

  if (wg_set_device(device.get()) < 0)
	throw WgException("Interface \"" + std::string(device->name) + "\" is unable to be set", errno);
}

template<typename TP>
void WgInterface<TP>::bringUp() {
  typename TP::Lock lock(mutex);
  bringAbstr(true);
}

template<typename TP>
void WgInterface<TP>::bringDown() {
  typename TP::Lock lock(mutex);
  bringAbstr(false);
}

template<typename TP>
void WgInterface<TP>::bringAbstr(bool up) {
  if (device == nullptr)
	return;

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
	throw WgException(std::string("Failed to create socket for interface \"") + device->name + '\"',
	                  errno);
  struct ifreq ifr{};
  std::strncpy(ifr.ifr_ifrn.ifrn_name, device->name, IFNAMSIZ);

  if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
	close(sock);
	throw WgException(
	    std::string("Failed to read configuration for interface \"") + device->name + '\"', errno);
  }

  if (up)
	ifr.ifr_ifru.ifru_flags |= IFF_UP;
  else
	ifr.ifr_ifru.ifru_flags &= ~IFF_UP;

  if (ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
	close(sock);
	throw WgException(std::string("Failed to set on interface \"") + device->name + '\"', errno);
  }
  close(sock);

  if (up)
	state = POWEREDON;
  else
	state = POWEREDOFF;
}

template<typename TP>
void WgInterface<TP>::release() noexcept {
  typename TP::Lock lock(mutex);
  if (device && state != UNREGISTERED) {
	try {
	  bringAbstr(false);
	} catch (...) {
	}
	wg_del_device(device->name);
	state = UNREGISTERED;

	device.reset();
  }

  peers.clear();
}

template<typename TP>
void WgInterface<TP>::setKey(WgKey<TP>&& key, KeyType type, bool force) {
  typename TP::Lock lock(mutex);
  if (device == nullptr)
	return;
  if (!force && state == POWEREDON) {
	throw WgException(
	    "Interface \"" + std::string(device->name) + "\" is up. Hot key change is not allowed",
	    1000);
  }

  // Set key anyway
  // Private key request automatically sets public one
  if (type == KeyType::PRIVATE) {
	std::memcpy(device->private_key, key.data(), WG_KEY_LEN);
	device->flags |= WGDEVICE_HAS_PRIVATE_KEY;

	wg_generate_public_key(device->public_key, device->private_key);
	device->flags |= WGDEVICE_HAS_PUBLIC_KEY;

	key.makeZero();
  }
}

template<typename TP>
bool WgInterface<TP>::tryValidateName(const char* name) const noexcept {
  return name && std::strlen(name) > 0 && std::strlen(name) < IFNAMSIZ;
}

template<typename TP>
void WgInterface<TP>::invalidatePeers() noexcept {
  if (device == nullptr)
	return;

  if (peers.empty()) {
	// Update links case there no peers left
	device->first_peer = nullptr;
	device->last_peer = nullptr;
  } else {
	device->first_peer = peers.front()->getStruct();

	auto first = peers.begin();
	auto second = std::next(first);

	while (second != peers.end()) {
	  WgPeer<TP>& p1 = *first->get();
	  WgPeer<TP>& p2 = *second->get();
	  p1.connectPeer(p2.getStruct());

	  ++first;
	  ++second;
	}

	WgPeer<TP>& lastPeer = *first->get();
	lastPeer.disconnectPeer();
	device->last_peer = lastPeer.getStruct();
  }
}

template<typename ThreadPolicy>
void WgInterface<ThreadPolicy>::setNameAbstr(const char* name) {
  if (device && state != UNREGISTERED)
	throw WgException(std::string("Cannot rename registered interface \"") + device->name + "\"",
	                  EPERM);

  if (interfaceExists(name))
	throw WgException(std::string("Interface \"") + name + "\" exists", errno);

  if (!tryValidateName(name))
	throw WgException(std::string("Invalid interface name \"") + name + "\"", EINVAL);

  if (device == nullptr) {
	device = std::make_unique<wg_device>();
	state = UNREGISTERED;
  }

  if (state == UNREGISTERED) {
	if (wg_add_device(name) < 0)
	  throw WgException("Unable to register interface name", errno);
	std::strcpy(device->name, name);
	state = POWEREDOFF;
  }
}

template<typename TP>
WgInterface<TP>& WgInterface<TP>::operator=(WgInterface&& other) noexcept {
  if (this != &other) {
	release();

	if constexpr (std::is_same_v<TP, MultiThreaded>) {
	  std::scoped_lock lock(this->mutex, other.mutex);

	  this->device = std::move(other.device);
	  this->state = other.state;
	  other.state = UNREGISTERED;
	  this->peers = std::move(other.peers);

	} else {
	  this->device = std::move(other.device);
	  this->state = other.state;
	  other.state = UNREGISTERED;
	  this->peers = std::move(other.peers);
	}
  }

  return *this;
}

#endif
