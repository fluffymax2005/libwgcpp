#include "wgprivatekey.h"


bool WgPrivateKey::isProper() const noexcept {
    return key && isGenerated;
}

void WgPrivateKey::generate() {
    if (key == nullptr)
        return;
    wg_generate_private_key(key->data());
    isGenerated = true;
}


