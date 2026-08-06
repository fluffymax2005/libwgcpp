/*
 * libwgcpp — C++ wrapper for embeddable-wg-library
 * Copyright (C) 2026  Ledovskiy Maksim aka fluffymax2005 <santech_montage@mail.ru>
 *
 * This file is part of libwgcpp.
 *
 * libwgcpp is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * libwgcpp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libwgcpp. If not, see <https://www.gnu.org/licenses/>.
*/

template<typename TP>
WgAllowedIP<TP>::WgAllowedIP(WgAllowedIP &&other) noexcept {
    if (this != &other) {
        this->ip = other.ip;
        other.ip.next_allowedip = nullptr;
    }
}

template<typename TP>
WgAllowedIP<TP>::WgAllowedIP() noexcept {
    // Default is "0.0.0.0/0"
    ip.family = AF_INET;
    ip.ip4.s_addr = 0;
    ip.cidr = 0;
}

template<typename TP>
WgAllowedIP<TP>::WgAllowedIP(const std::string& cidr) {
    setCIDR(cidr);
}

template<typename TP>
WgAllowedIP<TP>::WgAllowedIP(const char* cidr) {
    setCIDR(cidr);
}

template<typename TP>
bool WgAllowedIP<TP>::operator==(const WgAllowedIP &other) const noexcept {
    if (ip.family != other.ip.family)
        return false;
    if (ip.cidr != other.ip.cidr)
        return false;

    if (ip.family == AF_INET)
        return ip.ip4.s_addr == other.ip.ip4.s_addr;
    else
        return memcmp(&ip.ip6, &other.ip.ip6, sizeof(in6_addr)) == 0;
}

template<typename TP>
void WgAllowedIP<TP>::setCIDR(const std::string& cidr) {
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


    unsigned char buf[sizeof(struct in6_addr)];
    typename TP::Lock lock(mutex);
    if (inet_pton(AF_INET, addr_part.c_str(), buf) == 1) {
        if (prefix_len > 32)
            throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. IPv4 prefix cannot be more than 32");
        ip.family = AF_INET;
        std::memmove(&ip.ip4.s_addr, buf, sizeof(struct in_addr));
    } else if (inet_pton(AF_INET6, addr_part.c_str(), buf) == 1) {
        ip.family = AF_INET6;
        std::memmove(&ip.ip6, buf, sizeof(buf));
    } else {
        throw std::invalid_argument("CIDR \"" + cidr + "\" is not valid. CIDR from text to binary conversion failed");
    }

    ip.cidr = prefix_len;
}

template<typename TP>
void WgAllowedIP<TP>::setCIDR(const char* cidr) {
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

    unsigned char buf[sizeof(struct in6_addr)];
    typename TP::Lock lock(mutex);
    if (inet_pton(AF_INET, addr_part, buf) == 1) {
        if (prefix_len > 32)
            throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. IPv4 prefix cannot be more than 32");
        ip.family = AF_INET;
        std::memmove(&ip.ip4.s_addr, buf, sizeof(struct in_addr));
    } else if (inet_pton(AF_INET6, addr_part, buf) == 1) {
        ip.family = AF_INET6;
        std::memmove(&ip.ip6, buf, sizeof(buf));
    } else {
        throw std::invalid_argument(std::string("CIDR \"") + cidr + "\" is not valid. CIDR from text to binary conversion failed");
    }

    ip.cidr = prefix_len;
}

template<typename TP>
Protocol WgAllowedIP<TP>::getProto() const noexcept {
    return static_cast<Protocol>(ip.family);
}

template<typename TP>
std::string WgAllowedIP<TP>::getAddr() const {
    std::string addr;
    char buf[INET6_ADDRSTRLEN];
    if (ip.family == AF_INET) {
        addr = std::string(inet_ntop(AF_INET, &ip.ip4, buf, sizeof(buf)));
    } else {
        addr = std::string(inet_ntop(AF_INET6, &ip.ip6, buf, sizeof(buf)));
    }

    return addr;
}

template<typename TP>
std::string WgAllowedIP<TP>::getCIDR() const {
    return getAddr() + '/' + std::to_string(ip.cidr);
}

template<typename TP>
uint8_t WgAllowedIP<TP>::getCIDRNumber() const noexcept {
    return ip.cidr;
}

template<typename TP>
wg_allowedip* WgAllowedIP<TP>::getStruct() noexcept {
    return &ip;
}

template<typename TP>
void WgAllowedIP<TP>::connect(wg_allowedip* other) noexcept {
    if (other == nullptr)
        return;

    typename TP::Lock lock(mutex);
    ip.next_allowedip = other;
}

template<typename TP>
void WgAllowedIP<TP>::disconnect() noexcept {
    typename TP::Lock lock(mutex);
    ip.next_allowedip = nullptr;
}

template<typename TP>
WgAllowedIP<TP>& WgAllowedIP<TP>::operator=(WgAllowedIP&& other) noexcept {
    if (this != &other) {
        this->ip = other.ip;
        other.ip.next_allowedip = nullptr;
    }

    return *this;
}