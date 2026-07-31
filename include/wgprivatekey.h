#ifndef WGPRIVATEKEY_H
#define WGPRIVATEKEY_H

#include "wgkey.h"

class WgPrivateKey : public WgKey {
public:
    virtual bool isProper() const noexcept override;
    virtual void generate() override;
};

#endif // WGPRIVATEKEY_H
