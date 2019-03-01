/*
 * Copyright 2019 the bitcoinj-sv developers
 */
package org.bitcoinj.params;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.Utils;

import java.util.Date;
import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the Scaling Test Network, public network for testing fantastically big blocks.
 */
public class ScalingTestNetParams extends AbstractBitcoinNetParams {
    public ScalingTestNetParams() {
        super();
        id = ID_SCALINGTESTNET;
        // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        packetMagic = 0xfbcec4f9L;
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        port = 9333;
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTime(1296688602L);
        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setNonce(414098458);
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        alertSigningKey = Utils.HEX.decode("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");

        dnsSeeds = new String[] {
                "stn-seed.bitcoinsv.io"
        };
        addrSeeds = null;
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;

        majorityEnforceBlockUpgrade = TestNet2Params.TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TestNet2Params.TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TestNet2Params.TESTNET_MAJORITY_WINDOW;

        // Aug, 1 hard fork
        uahfHeight = 15;
        // Nov, 13 hard fork
        daaUpdateHeight = 2200;
        cashAddrPrefix = "bsvstn";
    }

    private static ScalingTestNetParams instance;
    public static synchronized ScalingTestNetParams get() {
        if (instance == null) {
            instance = new ScalingTestNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }

    // February 16th 2012
    private static final Date testnetDiffDate = new Date(1329264000000L);

    public static boolean isValidTestnetDateBlock(Block block){
        return block.getTime().after(testnetDiffDate);
    }

}






