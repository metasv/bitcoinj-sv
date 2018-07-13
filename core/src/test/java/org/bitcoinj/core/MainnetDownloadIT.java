package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStoreException;
import org.junit.Test;

public class MainnetDownloadIT extends ChainDownloadParent {

    public MainnetDownloadIT() throws BlockStoreException {
        super(new MainNetParams());
    }

    @Test
    public void testDownloadedChain() throws InterruptedException, BlockStoreException {
        sync();
        assert(blockChain.getBestChainHeight() > 538009);
        assert(blockStore.get(new Sha256Hash("000000000000000000079fc7ce821f88f4864358decd958b676235447e34619b")).getHeight() == 538007);
    }
}
