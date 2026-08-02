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

WgAllowedIP::WgAllowedIP(const std::string& cidr) noexcept {
    // Simple check (not sure for 100%) of CIDR notation
    const auto slash_pos = cidr.find_first_of('/');

    std::string addr_part;
    int prefix_len = 0;

    if (slash_pos != std::string::npos) {
        // Address part might exist
        addr_part = cidr.substr(0, slash_pos);

        // Prefix len might exist and must be tried to be extracted
        try {
            prefix_len = std::stoi(cidr.substr(slash_pos + 1));
        } catch (...) {
            // Default value
            prefix_len = 0;
        }
    } else {
        addr_part = cidr;
    }

    proto = determineInetFamily(addr_part.c_str());
    if (proto == Protocol::IPv4)
        ip.family = AF_INET;
    else
        ip.family = AF_INET6;

    void* buf;
    if (proto == Protocol::IPv4)
        buf = &ip.ip4;
    else
        buf = &ip.ip6;

    // If conversion failed then UB
    if (inet_pton(ip.family, addr_part.c_str(), buf) != 1)
        return;

    setCIDR(prefix_len);

}

WgAllowedIP::WgAllowedIP(const char* cidr) noexcept {
    // Simple check (not sure for 100%) of CIDR notation
    const auto* slash_pos = std::strchr(cidr, '/');

    char addr_part[INET6_ADDRSTRLEN + 1]{};
    int prefix_len = 0;

    if (slash_pos) {
        // Address part might exist
        std::strncpy(addr_part, cidr, slash_pos - cidr);

        // Prefix len might exist and must be tried to be extracted
        char* end;
        prefix_len = strtol(slash_pos + 1, &end, 10);
        if (*end != '\0' || prefix_len < 0 || prefix_len > 128)
            // Default value
            prefix_len = 0;
    } else {
        std::strcpy(addr_part, cidr);
    }

    proto = determineInetFamily(addr_part);
    if (proto == Protocol::IPv4)
        ip.family = AF_INET;
    else
        ip.family = AF_INET6;

    void* buf;
    if (proto == Protocol::IPv4)
        buf = &ip.ip4;
    else
        buf = &ip.ip6;

    // If conversion failed then UB
    if (inet_pton(ip.family, addr_part, buf) != 1)
        return;

    setCIDR(prefix_len);

}

bool WgAllowedIP::operator==(const WgAllowedIP &other) const noexcept {
    if (ip.family != other.ip.family)
        return false;
    if (ip.cidr != other.ip.cidr)
        return false;

    if (proto == Protocol::IPv4)
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

Protocol WgAllowedIP::determineInetFamily(const char* cidr) const noexcept {
    auto* dot = std::strchr(cidr, '.');
    if (dot != nullptr)
        return Protocol::IPv4;

    auto* colon = std::strchr(cidr, ':');
    if (colon != nullptr)
        return Protocol::IPv6;

    return Protocol::IPv4;
}

WgAllowedIP& WgAllowedIP::operator=(WgAllowedIP&& other) noexcept {
    if (this != &other) {
        this->proto = other.proto;
        this->ip = other.ip;
        other.ip = wg_allowedip();
    }

    return *this;
}
