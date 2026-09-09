#include <iostream>
#include <libwgcpp/wginterface.hpp>

int main() {

  using WgPrivateKey = WgPrivateKey<SingleThreaded>;
  using WgPublicKey = WgPublicKey<SingleThreaded>;
  using WgPeer = WgPeer<SingleThreaded>;
  using WgInterface = WgInterface<SingleThreaded>;

  const char *interfaceName = "wg0";

  try {

    // Create peer
    WgPeer peer;

    WgPrivateKey peerPrKey;
    WgPublicKey peerPbKey(peerPrKey);
    peer.setPublicKey(std::move(peerPbKey));

    // Create interface
    WgInterface interface(interfaceName);
    interface.setListenPort(1234);
    interface.addPeer(std::move(peer));

    interface.setPrivateKey(WgPrivateKey());

    interface.set();
    interface.bringUp();

    // NOTE: All required information about stored peers must be stored outside
    // of class. WgInterface does not give possibility to read peers' state in
    // order to provide thread safety by default.

  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return -1;
  }

  return 0;
}
