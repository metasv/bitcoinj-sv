package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStoreException;
import org.junit.Test;

public class TestnetDownloadIT extends ChainDownloadParent {

    public TestnetDownloadIT() throws BlockStoreException {
        super(new MainNetParams());
    }

    @Test
    public void testDownloadedChain() throws InterruptedException, BlockStoreException {
        sync();
        assert (blockChain.getBestChainHeight() > 1245531);
        assert (blockStore.get(new Sha256Hash("000000000000f8d83b0341531b39685b1cc2963d0086a9a64cf2de684b804be5")).getHeight() == 1245530);
    }
}

