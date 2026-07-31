#ifndef __WG_DEVICE__
#define __WG_DEVICE__

#include "wgexception.h"
#include "wgpublickey.h"
#include "wgpresharedkey.h"

#include <wireguard.h>
#include <string>
#include <cstdint>
#include <memory>
#include <vector>
#include <cstring>
#include <cerrno>

enum class ThreadSafety : uint8_t {
    SAFE,
    UNSAFE,
};

// TO DO
// Implement Thread safe and unsafe versions
//template<ThreadSafety = ThreadSafety::SAFE>
class WgInterface {
public:
    using WgKeyStringType = wg_key_b64_string;

    virtual ~WgInterface() noexcept;

    WgInterface(const WgInterface&) = delete;
    WgInterface& operator=(const WgInterface&) noexcept = delete;

    WgInterface(WgInterface&& other) noexcept;
    WgInterface& operator=(WgInterface&& other) noexcept;

    WgInterface(const std::string& name) noexcept;
    WgInterface(const char* name) noexcept;

    bool inline hasDevice() const noexcept;
    bool inline hasPrivateKey() const noexcept;
    bool inline isListening() const noexcept;
    bool inline isSet() const noexcept;

    virtual void setName(const std::string& name) noexcept;
    virtual void setName(const char* name) noexcept;

    virtual void setPrivateKey(WgPrivateKey& private_key, bool force = false);

    // TO DO
    // Change wg_peer with self implemented version later
    virtual void addPeer(wg_peer peer) noexcept(false);

    virtual void set() noexcept(false);
    virtual void release() noexcept(false);
    virtual void poweroff() noexcept(false);

    std::vector<std::string> getPeers() const;

protected:
    std::unique_ptr<wg_device> device;
    bool isInterfaceSet{false};

    enum KeyType : uint8_t {
        PRESHARED,
        PRIVATE,
        PUBLIC,
    };

    void setKey(WgKey& key, KeyType type, bool force = false);

    virtual void setPublicKey(WgPrivateKey& private_key, bool force = false);

    static inline uint16_t ID{0};
};

#endif