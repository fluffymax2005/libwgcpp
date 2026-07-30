#include "wginterface.h"


WgInterface::~WgInterface() noexcept {
    if (isInterfaceSet)
        release();
}

WgInterface::WgInterface(WgInterface &&other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->isInterfaceSet = other.isInterfaceSet;
        other.isInterfaceSet = false;
    }
}

WgInterface::WgInterface(const std::string &name) noexcept {
    device = std::make_unique<wg_device>();
    if (device == nullptr)
        return;

    char pname[IFNAMSIZ];
    if (name.length() == 0) {
        strcpy(pname, "wg");
        snprintf(pname + 2, sizeof(pname) - 2, "%d", ID++);
    } else if (name.length() < IFNAMSIZ) {
        strncpy(pname, name.c_str(), name.length());
    } else {
        return;
    }

    strcpy(device->name, pname);
}

WgInterface::WgInterface(const char *name) noexcept {
    device = std::make_unique<wg_device>();
    if (device == nullptr)
        return;

    char pname[IFNAMSIZ];
    if (name == nullptr || strlen(name) == 0) {
        strcpy(pname, "wg");
        snprintf(pname + 2, sizeof(pname) - 2, "%d", ID++);
    } else if (strlen(name) < IFNAMSIZ) {
        strncpy(pname, name, strlen(name));
    } else {
        return;
    }

    strcpy(device->name, pname);
}

bool WgInterface::hasDevice() const noexcept {
    return device.get();
}

bool WgInterface::hasPrivateKey() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_PRIVATE_KEY;
    }
}

bool WgInterface::isListening() const noexcept {
    if (device) {
        return device->flags & WGDEVICE_HAS_LISTEN_PORT && device->listen_port;
    }
    return false;
}

bool WgInterface::isSet() const noexcept {
    return isInterfaceSet;
}

void WgInterface::setName(const std::string &name) noexcept {
    if (device) {
        if (isInterfaceSet)
            poweroff();

        char pname[IFNAMSIZ];
        if (name.length() == 0) {
            strcpy(pname, "wg");
            snprintf(pname + 2, sizeof(pname) - 2, "%d", ID);
        } else if (name.length() < IFNAMSIZ) {
            strncpy(pname, name.c_str(), name.length());
        } else {
            return;
        }

        strcpy(device->name, pname);

        set();
    }
}

void WgInterface::setName(const char *name) noexcept {
    if (device) {
        if (isInterfaceSet)
            poweroff();

        char pname[IFNAMSIZ];
        if (name == nullptr || strlen(name) == 0) {
            strcpy(pname, "wg");
            snprintf(pname + 2, sizeof(pname) - 2, "%d", ID);
        } else if (strlen(name) < IFNAMSIZ) {
            strncpy(pname, name, strlen(name));
        } else {
            return;
        }

        strcpy(device->name, pname);

        set();
    }
}

void WgInterface::setPrivateKey(wg_key private_key, bool force) {
    setKey(private_key, KeyType::PRIVATE, force);
}

void WgInterface::setPresharedKey(wg_key preshared_key, bool force) {
    setKey(preshared_key, KeyType::PRESHARED, force);
}

void WgInterface::set() noexcept(false) {
    if (isInterfaceSet)
        return;

}

void WgInterface::release() noexcept(false) {

}

void WgInterface::poweroff() noexcept(false) {

}

std::vector<std::string> WgInterface::getPeers() const {
    char* device_names;
    char* device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (device_names == nullptr)
        throw WgException("Not enough memory for device names", errno);

    wg_device* device;
    wg_peer* peer;
    wg_key_b64_string key;

    if (wg_get_device(&device, device_name) < 0)
        throw WgException("Unable to get interface", errno);
    std::vector<std::string> peers;
    wg_for_each_peer(device, peer) {
        wg_key_to_base64(key, peer->public_key);
        try {
            peers.push_back(key);
        } catch (const std::bad_alloc& e) {
            throw WgException(std::string("Unable to get peer's key. Reason: ") + e.what(), 0);
        }
    }
}

void WgInterface::setKey(wg_key key, KeyType type, bool force) {
    if (device == nullptr)
        return;
    if (!force) {
        if (isInterfaceSet)
            throw WgException("Interface \"" + std::string(device->name) + "\" is up. Hot key change is not allowed", 1000);
        // TO DO
        // Implement WgPublic, WgPrivate and WgPreshared keys which can generate keys itself and integrate it here
    }
}

void WgInterface::setPublicKey(wg_key private_key, bool force) {
    setKey(private_key, KeyType::PUBLIC, force);
}

WgInterface& WgInterface::operator=(WgInterface&& other) noexcept {
    if (this != &other) {
        release();

        this->device = std::move(other.device);
        this->isInterfaceSet = other.isInterfaceSet;
        other.isInterfaceSet = false;
    }

    return *this;
}


