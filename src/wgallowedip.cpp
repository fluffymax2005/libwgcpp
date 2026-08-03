#include "wgallowedip.h"


WgAllowedIP::WgAllowedIP(WgAllowedIP &&other) noexcept {
    if (this != &other) {
        this->ip = other.ip;
        other.ip.next_allowedip = nullptr;
    }
}

WgAllowedIP::WgAllowedIP() noexcept {
    // Default is "0.0.0.0/0"
    ip.family = AF_INET;
    ip.ip4.s_addr = 0;
    ip.cidr = 0;
}

WgAllowedIP::WgAllowedIP(const std::string& cidr) {
    setCIDR(cidr);
}

WgAllowedIP::WgAllowedIP(const char* cidr) {
    setCIDR(cidr);
}

bool WgAllowedIP::operator==(const WgAllowedIP &other) const noexcept {
    if (ip.family != other.ip.family)
        return false;
    if (ip.cidr != other.ip.cidr)
        return false;

    if (ip.family == AF_INET)
        return ip.ip4.s_addr == other.ip.ip4.s_addr;
    else
        return memcmp(&ip.ip6, &other.ip.ip6, sizeof(in6_addr)) == 0;
}

void WgAllowedIP::setCIDR(const std::string& cidr) {
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
            throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. Prefix conversion failed");
        }

        if (prefix_len < 0 || prefix_len > 128)
            throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. Prefix value is not in range [0; 128]");

    } else {
        throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. Prefix is not found");
    }

    ip.family = static_cast<uint16_t>(determineInetFamily(addr_part.c_str()));

    void* buf;
    if (ip.family == AF_INET) {
        if (prefix_len > 32)
            throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. IPv4 prefix cannot be more than 32");
        buf = &ip.ip4;
    } else {
        buf = &ip.ip6;
    }


    // If conversion failed then object is in invalid state
    if (inet_pton(ip.family, addr_part.c_str(), buf) != 1)
        throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. CIDR from text to binary conversion failed");

    ip.cidr = prefix_len;
}

void WgAllowedIP::setCIDR(const char* cidr) {
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

        if (*end != '\0')
            throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. Prefix conversion failed");
        if (prefix_len < 0 || prefix_len > 128)
            throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. Prefix value is not in range [0; 128]");
    } else {
        throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. Prefix is not found");
    }

    ip.family = static_cast<uint16_t>(determineInetFamily(addr_part));

    void* buf;
    if (ip.family == AF_INET) {
        if (prefix_len > 32)
            throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. IPv4 prefix cannot be more than 32");
        buf = &ip.ip4;
    } else {
        buf = &ip.ip6;
    }

    // If conversion failed then UB
    if (inet_pton(ip.family, addr_part, buf) != 1)
        throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. CIDR from text to binary conversion failed");

    ip.cidr = prefix_len;
}

Protocol WgAllowedIP::getProto() const noexcept {
    return static_cast<Protocol>(ip.family);
}

std::string WgAllowedIP::getAddr() const {
    std::string addr;
    int domain;
    char buf[INET6_ADDRSTRLEN];
    if (ip.family == AF_INET) {
        addr = std::string(inet_ntop(AF_INET, &ip.ip4, buf, sizeof(buf)));
    } else {
        addr = std::string(inet_ntop(AF_INET6, &ip.ip6, buf, sizeof(buf)));
    }

    return addr;
}

uint8_t WgAllowedIP::getCIDRNumber() const noexcept {
    return ip.cidr;
}

wg_allowedip* WgAllowedIP::getStruct() noexcept {
    return &ip;
}

void WgAllowedIP::connect(wg_allowedip* other) noexcept {
    if (other)
        ip.next_allowedip = other;
}

void WgAllowedIP::disconnect() noexcept {
    ip.next_allowedip = nullptr;
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
        this->ip = other.ip;
        other.ip.next_allowedip = nullptr;
    }

    return *this;
}
