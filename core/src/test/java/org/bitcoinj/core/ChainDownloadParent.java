package org.bitcoinj.core;

import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.net.BlockingClientManager;
import org.bitcoinj.net.ClientConnectionManager;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;

public class ChainDownloadParent {

    protected NetworkParameters parameters;
    protected Context context;
    protected BlockStore blockStore;
    protected BlockChain blockChain;
    protected ClientConnectionManager connectionManager;
    protected PeerGroup peerGroup;

    public ChainDownloadParent(NetworkParameters parameters) throws BlockStoreException {
        this.parameters = parameters;
        this.context = new Context(parameters);
        this.blockStore = new MemoryBlockStore(parameters);
        this.blockChain = new BlockChain(context, blockStore);
        this.connectionManager = new BlockingClientManager();
        this.peerGroup = new PeerGroup(context, blockChain, connectionManager);
        peerGroup.addPeerDiscovery(new DnsDiscovery(parameters));
    }

    public void sync() throws InterruptedException {
        DownloadProgressTracker listener = new DownloadProgressTracker();
        peerGroup.start();
        peerGroup.startBlockChainDownload(listener);
        listener.await();
    }
}
