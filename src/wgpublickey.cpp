#include "wgpublickey.h"


WgPublicKey::WgPublicKey(std::shared_ptr<WgPrivateKey> private_key)
    : private_key(private_key){
    key = std::make_shared<std::array<uint8_t, WG_KEY_LEN>>();
}

bool WgPublicKey::isProper() const noexcept {
    return key && isGenerated;
}

void WgPublicKey::generate() {
    if (key == nullptr)
        return;
    auto priv = private_key.lock();
    if (priv == nullptr)
        throw std::runtime_error("Private key no longer exists");
    wg_generate_public_key(key->data(), priv->data());
    isGenerated = true;
}
