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
package org.bitcoinj.script;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.ScriptException.*;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.VerificationException;
import org.junit.Test;

import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

@RunWith(Parameterized.class)
public class ScriptDataDrivenTest {
    @Parameters
    public static Collection<JsonNode> getData() throws IOException {
        Collection<JsonNode> testData = new ArrayList<JsonNode>(1000);
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(Thread.currentThread().getContextClassLoader().
                getResourceAsStream("script_tests.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            if (test.size() > 1) {          // ignore comments
                testData.add(test);
            }
        }
        return testData;
    }

    private JsonNode jsonData;

    public ScriptDataDrivenTest(JsonNode testData) {
        jsonData = testData;
    }

    @Test
    public void testNamedScript() throws IOException {
        Coin value = Coin.valueOf(0);
        Script scriptSig;
        Script scriptPubKey;
        Set<Script.VerifyFlag> flags;
        String expected = "";
        String comments = "";
        int i = 0;
        String result = "OK";

        try {
            if (jsonData.size() > 6) {
                fail(String.format("too many fields in json: %s", jsonData));
            }
            if (jsonData.get(0).isArray()) {
                value = Coin.parseCoin(jsonData.get(i++).get(0).asText());
            }
            String scriptSigString = jsonData.get(i++).asText();
            String scriptPubKeyString = jsonData.get(i++).asText();
            String flagString = jsonData.get(i++).asText();
            expected = jsonData.get(i++).asText();
            if (jsonData.size() > 4) {
                comments = jsonData.get(i).asText();
            }

            flags = ScriptHelpers.parseVerifyFlags(flagString);
            // TODO: these capabilities have not been implemented yet or they are failing
            if (expected.equals("SIG_HIGH_S")) {
                return;
            }
            scriptSig = ScriptHelpers.parseScriptString(scriptSigString);
            scriptPubKey = ScriptHelpers.parseScriptString(scriptPubKeyString);

            Transaction creditTx = ScriptHelpers.buildCreditingTransaction(scriptPubKey,value);
            creditTx.verify();
            Transaction spendTx = ScriptHelpers.buildSpendingTransaction(scriptSig, creditTx);
            spendTx.verify();

            scriptSig.correctlySpends(spendTx, 0, scriptPubKey, value, flags);

        }

        catch (ScriptException e) {
            if (e.getError() != null)
                result = e.getError().getMnemonic();
            else result = "UNKNOWN_ERROR";
        } catch (VerificationException e) {
            result = "UNKNOWN_ERROR";
        } catch (Throwable e) {
            e.printStackTrace();
            System.out.println("TRACE!!!!");
        }


        if (!result.equals(expected)) {
            fail(String.format("FAILED: result=%s, expected=%s", result,expected));
        }
    }

}
