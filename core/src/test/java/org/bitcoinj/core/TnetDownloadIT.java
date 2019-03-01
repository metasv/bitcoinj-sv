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

import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;

// note: can call this TestnetDownloadIT otherwise it gets included in the unit tests

public class TnetDownloadIT {

    static DownloadedChainData data = null;

    @Before
    public void setup() throws InterruptedException, BlockStoreException {
        Utils.mockTime = null;
        if (data == null) {
            data = new DownloadedChainData(new TestNet3Params());
            List<String> mnemonic = Arrays.asList("topic", "scorpion", "vehicle", "mimic", "kidney", "focus", "weekend",
                    "certain", "version", "area", "topple", "file");
            DeterministicSeed seed = new DeterministicSeed(mnemonic, null, "", 1531520999);
            Wallet wallet = Wallet.fromSeed(data.parameters, seed);
            data.setupAndSync(wallet);
        }
    }

    /**
     * check that the chain is higher than a given height and that a specific block is included
     * @throws BlockStoreException
     */
    @Test
    public void testDownloadedChain() throws BlockStoreException {
        assertTrue(data.blockChain.getBestChainHeight() > 1245531);
//        assertEquals(1245530, data.blockStore.get(new Sha256Hash("000000000000f8d83b0341531b39685b1cc2963d0086a9a64cf2de684b804be5")).getHeight());
    }

    /**
     * send & receive to self
     */
    @Test
    @Ignore
    public void testSendReceive() throws InsufficientMoneyException, ExecutionException, InterruptedException {
        assertNotEquals("wallet balance is zero", data.wallet.getBalance(), Coin.ZERO);

        // send to self
        Address destination = data.wallet.freshReceiveAddress();
        Coin startBalance = data.wallet.getBalance();
        SendRequest req = SendRequest.to(destination, startBalance.div(4));
        req.setUseForkId(true);
        data.wallet.completeTx(req);
        TransactionBroadcast broadcast = data.peerGroup.broadcastTransaction(req.tx);
        Transaction sent = broadcast.future().get();
        System.out.println(String.format("sent tx, txid=%s", sent.getHashAsString()));
        assertTrue(sent.isMature());

        // check my balance, it should be greater than 0.9* initial balance
        assertTrue(data.wallet.getBalance(Wallet.BalanceType.ESTIMATED).isGreaterThan(startBalance.minus(startBalance.div(10))));
    }
}

