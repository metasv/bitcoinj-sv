/*
 * Copyright 2019 the bitcoinj-sv developers
 *
 */
package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.ScalingTestNetParams;
import org.bitcoinj.store.BlockStoreException;
import org.junit.Before;
import org.junit.Test;

public class STNDownloadIT {

    static DownloadedChainData data = null;

    @Before
    public void setup() throws InterruptedException, BlockStoreException {
        Utils.mockTime = null;
        if (data == null) {
            data = new DownloadedChainData(new ScalingTestNetParams());
            data.setupAndSync(null);
        }
    }

    /**
     * check that the chain is higher than a given height and that a specific block is included
     * @throws BlockStoreException
     */
    @Test
    public void testDownloadedChain() throws BlockStoreException {
        assert(data.blockChain.getBestChainHeight() > 2000);
    }
}

