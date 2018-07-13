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
