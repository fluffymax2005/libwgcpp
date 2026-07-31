#ifndef WGPRESHAREDKEY_H
#define WGPRESHAREDKEY_H

#include "wgkey.h"

class WgPresharedKey : public WgKey {
public:
    WgPresharedKey();

    virtual bool isProper() const noexcept override;
    virtual void generate() override;
};

#endif // WGPRESHAREDKEY_H
