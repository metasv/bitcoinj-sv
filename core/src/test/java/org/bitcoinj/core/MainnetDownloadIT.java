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

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStoreException;
import org.junit.Before;
import org.junit.Test;

public class MainnetDownloadIT {

    static DownloadedChainData data = null;

    @Before
    public void setup() throws InterruptedException, BlockStoreException {
        Utils.mockTime = null;
        if (data == null) {
            data = new DownloadedChainData(new MainNetParams());
            data.setupAndSync(null);
        }
    }

    /**
     * check that the chain is higher than a given height and that a specific block is included
     * @throws BlockStoreException
     */
    @Test
    public void testDownloadedChain() throws BlockStoreException {
        assert(data.blockChain.getBestChainHeight() > 571806);
        assert(data.blockStore.get(new Sha256Hash("00000000000000000891f8f76a025cfb7a1b8e9fb0c30eb9b7e1dd1a17e0ee8b")).getHeight() == 571806);
    }
}
