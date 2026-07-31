#ifndef WGKEY_H
#define WGKEY_H

#include "wireguard.h"

#include <cstdint>
#include <memory>
#include <array>
#include <cstring>

constexpr uint32_t WG_KEY_LEN = sizeof(wg_key);

enum class KeyType : uint8_t {
    PRESHARED,
    PRIVATE,
    PUBLIC,
};

inline enum wg_device_flags operator|(enum wg_device_flags a, enum wg_device_flags b) {
    return static_cast<wg_device_flags>(
        static_cast<int>(a) | static_cast<int>(b)
    );
}

inline enum wg_device_flags& operator|=(enum wg_device_flags& a, enum wg_device_flags b) {
    a = a | b;
    return a;
}

class WgKey {
public:
    virtual ~WgKey() = default;

    virtual bool isProper() const noexcept = 0;
    virtual void generate() = 0;

    const uint8_t* data() const noexcept;
    uint32_t size() const noexcept;
    std::shared_ptr<std::array<uint8_t, WG_KEY_LEN>> cloneData() const noexcept;
    bool initialize() noexcept;
    void makeZero() noexcept;

protected:
    std::shared_ptr<std::array<uint8_t, WG_KEY_LEN>> key{nullptr};

    bool isGenerated{false};
};

#endif // WGKEY_H
