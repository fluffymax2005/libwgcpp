#include "wgallowedip.h"


WgAllowedIP::WgAllowedIP(WgAllowedIP &&other) noexcept {
    if (this != &other) {
        this->proto = other.proto;
        this->ip = other.ip;
        other.ip = wg_allowedip();
    }
}

WgAllowedIP::WgAllowedIP(Protocol proto) noexcept
    : proto{proto} {
    if (proto == Protocol::IPv4) {
        ip.family = AF_INET;
    } else {
        ip.family = AF_INET6;
    }

}

bool WgAllowedIP::operator==(const WgAllowedIP &other) const noexcept {
    if (ip.family != other.ip.family)
        return false;
    if (ip.cidr != other.ip.cidr)
        return false;

    if (proto == IPv4)
        return ip.ip4.s_addr == other.ip.ip4.s_addr;
    else
        return memcmp(&ip.ip6, &other.ip.ip6, sizeof(in6_addr)) == 0;
}

void WgAllowedIP::setCIDR(uint8_t cidr) noexcept {
    if (proto == Protocol::IPv4) {
        if (cidr <= 24)
            ip.cidr = cidr;
        else
            ip.cidr = 0;
    } else {
        ip.cidr = cidr;
    }
}

void WgAllowedIP::setIPAddr(const std::string& addr) {
    setIPAddr(addr.c_str());
}

void WgAllowedIP::setIPAddr(const char *addr) {
    int8_t code;
    if (proto == Protocol::IPv4)
        code = inet_pton(ip.family, addr, &ip.ip4);
    else
        code = inet_pton(ip.family, addr, &ip.ip6);
    if (code == 0)
        throw WgException("IP address conversion failed. Invalid network address of specified address family provided", errno);
}

wg_allowedip* WgAllowedIP::getStruct() noexcept {
    return &ip;
}

WgAllowedIP& WgAllowedIP::operator=(WgAllowedIP&& other) noexcept {
    if (this != &other) {
        this->proto = other.proto;
        this->ip = other.ip;
        other.ip = wg_allowedip();
    }

    return *this;
}
