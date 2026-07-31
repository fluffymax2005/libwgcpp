#ifndef WGPUBLICKEY_H
#define WGPUBLICKEY_H

#include "wgprivatekey.h"

class WgPublicKey : public WgKey {
public:
    WgPublicKey(std::shared_ptr<WgPrivateKey> private_key);

    virtual bool isProper() const noexcept override;
    virtual void generate() override;

private:
    std::weak_ptr<WgPrivateKey> private_key;
};

#endif // WGPUBLICKEY_H
