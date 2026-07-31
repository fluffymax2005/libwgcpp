#include "wgkey.h"

const uint8_t* WgKey::data() const noexcept {
    return key ? key->data() : nullptr;
}

uint32_t WgKey::size() const noexcept {
    return WG_KEY_LEN;
}

std::shared_ptr<std::array<uint8_t, WG_KEY_LEN>> WgKey::cloneData() const noexcept {
    if (key == nullptr)
        return nullptr;
    return std::make_shared<std::array<uint8_t, WG_KEY_LEN>>(*key);
}

bool WgKey::initialize() noexcept {
    if (key)
        return false;
    key = std::make_shared<std::array<uint8_t, WG_KEY_LEN>>();
    return key->empty();
}

void WgKey::makeZero() noexcept {
    if (key == nullptr || key->data() == nullptr)
        return;
    std::memcpy(key->data(), 0, WG_KEY_LEN);
    isGenerated = false;
}
