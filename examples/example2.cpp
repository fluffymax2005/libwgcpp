#include "wginterface.h"
#include "wgendpoint.h"

#include <iostream>
#include <chrono>
#include <thread>

int main() {
    using WgAllowedIP = WgAllowedIP<SingleThreaded>;
    using WgEndpoint = WgEndpoint<SingleThreaded>;
    using WgPrivateKey = WgPrivateKey<SingleThreaded>;
    using WgPresharedKey = WgPresharedKey<SingleThreaded>;
    using WgPublicKey = WgPublicKey<SingleThreaded>;
    using WgPeer = WgPeer<SingleThreaded>;
    using WgInterface = WgInterface<SingleThreaded>;

    const char* interfaceName = "wg10";

    try {

        // Configure client's peer - server
        WgPresharedKey prsKey;
        WgPublicKey pbKey{WgPrivateKey()};

        WgPeer peer(&pbKey, &prsKey);
        peer.addAllowedIP(WgAllowedIP("192.168.1.0/24"));
        peer.setEndpoint(WgEndpoint::create("123.123.123.123", 51820));
        peer.setPersistentKeepAlive(25);

        // Configure client interface
        WgInterface interface{interfaceName};
        interface.setPrivateKey(WgPrivateKey());
        interface.setListeningPort(51820);
        interface.addPeer(std::move(peer));
        interface.set();

        auto peers = interface.getPeers();
        std::cout << "Interface with name \"" << interface.getName() << "\" has "
                  << peers.size() << " peer(s)\n";
        for (size_t i = 0; i < peers.size(); i++)
            std::cout << "peer " << i << ": " << peers[i] << '\n';

        std::cout << '\"' << interface.getName() << "\" listens on port " << interface.getPort() << '\n';
        std::cout << '\"' << interface.getName() << "\" has fwmark = " << interface.getFWMark() << std::endl;

        // Sleep some time so user could investigate interface appearance
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10s);

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}