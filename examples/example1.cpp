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
        interfacePrKey.generate();

        interface.setPrivateKey(std::move(interfacePrKey));

        interface.set();

        // Print
        const auto peers = interface.getPeers();
        std::cout << "Interface \"" << interfaceName << "\" has "<< peers.size() << " peers" << std::endl;
        for (const auto& str : peers) {
            std::cout << "Interface \"" << interfaceName << "\" has peer with public key \"" << str << "\"" << std::endl;
        }

    } catch (const WgException& e) {
        std::cout << e.what() << std::endl;
    } catch (const std::runtime_error& e) {
        std::cout << e.what() << std::endl;
    }



    return 0;
}