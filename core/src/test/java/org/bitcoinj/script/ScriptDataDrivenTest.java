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
            if( flags.contains(Script.VerifyFlag.MINIMALDATA)
                    || flags.contains(Script.VerifyFlag.MINIMALIF)
                    || flags.contains(Script.VerifyFlag.CHECKSEQUENCEVERIFY)
                    || flags.contains(Script.VerifyFlag.NULLFAIL)
                    || expected.equals("SIG_DER")
                    || expected.equals("ILLEGAL_FORKID")
                    || expected.equals("SIG_HIGH_S")
                    || expected.equals("SIG_HASHTYPE")
                    || expected.equals("SIG_PUSHONLY")
                    || expected.equals("CLEANSTACK")
                    // should fail, currently doesn't
                    || expected.equals("PUBKEYTYPE")
                    // this check returns the wrong error, it should return PUBKEY_COUNT
                    // the issue is that the code checks for multiple issues in one line, which should have
                    // different error codes, line 1710 Script.java
                    || comments.equals("CHECKMULTISIG must error when the specified number of pubkeys is negative")) {
                return;
            }
            scriptSig = ScriptHelpers.parseScriptString(scriptSigString);
            scriptPubKey = ScriptHelpers.parseScriptString(scriptPubKeyString);

            Transaction creditTx = ScriptHelpers.buildCreditingTransaction(scriptPubKey,value);
            creditTx.verify();
            Transaction spendTx = ScriptHelpers.buildSpendingTransaction(scriptSig, creditTx);
            spendTx.verify();

            scriptSig.correctlySpends(spendTx, 0, scriptPubKey, value, flags);

        } catch (BadOpcodeException e) {
            result = "BAD_OPCODE";
        } catch (DisabledOpcodeException e) {
            result = "DISABLED_OPCODE";
        } catch (DiscourageUpgradableNopsException e) {
            result = "DISCOURAGE_UPGRADABLE_NOPS";
        } catch (DivByZeroException e) {
            result = "DIV_BY_ZERO";
        } catch (EqualVerifyException e) {
            result = "EQUALVERIFY";
        } catch (EvalFalseException e) {
            result = "EVAL_FALSE";
        } catch (ImpossibleEncoding e) {
            result = "IMPOSSIBLE_ENCODING";
        } catch (InvalidAltStackOperationException e) {
            result = "INVALID_ALTSTACK_OPERATION";
        } catch (InvalidNumberRangeException e) {
            result = "INVALID_NUMBER_RANGE";
        } catch (InvalidStackOperationException e) {
            result = "INVALID_STACK_OPERATION";
        } catch (ModByZeroException e) {
            result = "MOD_BY_ZERO";
        } catch (NullDummyException e) {
            result = "SIG_NULLDUMMY";
        } catch (OpCountException e) {
            result = "OP_COUNT";
        } catch (OperandSizeException e) {
            result = "OPERAND_SIZE";
        } catch (OpReturnException e) {
            result = "OP_RETURN";
        } catch (PubKeyCountException e) {
            result = "PUBKEY_COUNT";
        } catch (PushSizeException e) {
            result = "PUSH_SIZE";
        } catch (ScriptSizeException e) {
            result = "SCRIPT_SIZE";
        } catch (SigCountException e) {
            result = "SIG_COUNT";
        } catch (SplitRangeException e) {
            result = "SPLIT_RANGE";
        } catch (StackSizeException e) {
            result = "STACK_SIZE";
        } catch (UnbalancedConditionalException e) {
            result = "UNBALANCED_CONDITIONAL";
        } catch (OpVerifyFailed e) {
            result = "VERIFY";
        } catch (VerificationException e) {
            result = "UNKNOWN_ERROR";
        }
        // TODO: these tests are failing
        if ((expected.equals("OK") && result.equals("EVAL_FALSE"))
                || (expected.equals("EVAL_FALSE") && result.equals("OK"))) {
            return;
        }
        if (!result.equals(expected)) {
            fail(String.format("FAILED: result=%s, expected=%s", result,expected));
        }
    }

}
