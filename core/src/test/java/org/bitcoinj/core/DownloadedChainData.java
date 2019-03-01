/*
 * Copyright 2018 the bitcoinj-cash developers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.core;

import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.net.BlockingClientManager;
import org.bitcoinj.net.ClientConnectionManager;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.wallet.Wallet;

import java.util.ArrayList;
import java.util.List;

/**
 * helper class to hold a downloaded chain and wallet
 * this is bad practice, but necessary for the MainnetDownloadIT and TnetDownloadIT integration tests
 */
public class DownloadedChainData {
    public NetworkParameters parameters;
    public Context context;
    public BlockStore blockStore;
    public BlockChain blockChain;
    public ClientConnectionManager connectionManager;
    public PeerGroup peerGroup;
    public Wallet wallet;

    public DownloadedChainData(NetworkParameters parameters) {
        this.parameters = parameters;
        this.context = new Context(parameters);
        Context.propagate(this.context);
    }

    public void setupAndSync(Wallet wallet) throws InterruptedException, BlockStoreException {
        List<Wallet> wallets = new ArrayList<>(1);
        this.wallet = wallet;
        if (wallet != null) {
            wallets.add(wallet);
        }
        this.blockStore = new MemoryBlockStore(parameters);
        this.blockChain = new BlockChain(context, wallets, blockStore);
        this.connectionManager = new BlockingClientManager();
        this.peerGroup = new PeerGroup(context, blockChain, connectionManager);
        peerGroup.addPeerDiscovery(new DnsDiscovery(parameters));
        peerGroup.setFastCatchupTimeSecs(Utils.currentTimeSeconds()-3600);

        DownloadProgressTracker listener = new DownloadProgressTracker();
        peerGroup.start();
        peerGroup.startBlockChainDownload(listener);
        listener.await();
    }
}
