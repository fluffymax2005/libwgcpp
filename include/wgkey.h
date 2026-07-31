#ifndef WGKEY_H
#define WGKEY_H

#include "wireguard.h"

#include <cstdint>
#include <memory>
#include <array>
#include <cstring>

constexpr uint32_t WG_KEY_LEN = sizeof(wg_key);

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
