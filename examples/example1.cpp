#include "wginterface.h"
#include <iostream>

int main() {

    const char* interfaceName = "wg0";

    try {

        // Create peer
        WgPeer peer;

        WgPrivateKey peerPrKey;
        WgPublicKey peerPbKey(peerPrKey);
        peer.setPublicKey(std::move(peerPbKey));

        // Create interface
        WgInterface interface(interfaceName);
        interface.setListeningPort(1234);
        interface.addPeer(std::move(peer));

        WgPrivateKey interfacePrKey;

        interface.setPrivateKey(std::move(interfacePrKey));

        interface.set();

        // Print
        const auto peers = interface.getPeers();
        std::cout << "Interface \"" << interfaceName << "\" has "<< peers.size() << " peers" << std::endl;
        for (const auto& str : peers) {
            std::cout << "Interface \"" << interfaceName << "\" has peer with public key \"" << str << "\"" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}