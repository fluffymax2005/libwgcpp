#include "wgpresharedkey.h"


WgPresharedKey::WgPresharedKey() {
    key = std::make_shared<std::array<uint8_t, WG_KEY_LEN>>();
}

bool WgPresharedKey::isProper() const noexcept {
    return key && isGenerated;
}

void WgPresharedKey::generate() {
    if (key == nullptr)
        return;
    wg_generate_preshared_key(key->data());
    isGenerated = true;
}
