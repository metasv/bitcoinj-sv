package org.bitcoinj.script;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.bitcoinj.core.Utils.HEX;

/**
 *A simple demonstration of ScriptStateListener that dumps the state of the state to console after each op code execution.
 *
 * Created by shadders on 7/02/18.
 */
public class InteractiveScriptStateListener extends ScriptStateListener {

    private String fullScriptString;
    private boolean pauseForUser = true;

    public static void main(String[] args) {

        NetworkParameters params = MainNetParams.get();

        String rawTransaction = "0100000002d8c8df6a6fdd2addaf589a83d860f18b44872d13ee6ec3526b2b470d42a96d4d000000008b483045022100b31557e47191936cb14e013fb421b1860b5e4fd5d2bc5ec1938f4ffb1651dc8902202661c2920771fd29dd91cd4100cefb971269836da4914d970d333861819265ba014104c54f8ea9507f31a05ae325616e3024bd9878cb0a5dff780444002d731577be4e2e69c663ff2da922902a4454841aa1754c1b6292ad7d317150308d8cce0ad7abffffffff2ab3fa4f68a512266134085d3260b94d3b6cfd351450cff021c045a69ba120b2000000008b4830450220230110bc99ef311f1f8bda9d0d968bfe5dfa4af171adbef9ef71678d658823bf022100f956d4fcfa0995a578d84e7e913f9bb1cf5b5be1440bcede07bce9cd5b38115d014104c6ec27cffce0823c3fecb162dbd576c88dd7cda0b7b32b0961188a392b488c94ca174d833ee6a9b71c0996620ae71e799fc7c77901db147fa7d97732e49c8226ffffffff02c0175302000000001976a914a3d89c53bb956f08917b44d113c6b2bcbe0c29b788acc01c3d09000000001976a91408338e1d5e26db3fce21b011795b1c3c8a5a5d0788ac00000000";

        byte[] txBytes = HEX.decode(rawTransaction);
        Transaction tx = new Transaction(params, txBytes);
        Script scriptSig = tx.getInput(0).getScriptSig();
        Script scriptPubKey = tx.getOutput(0).getScriptPubKey();

        LinkedList<byte[]> stack = new LinkedList();

        ScriptStateListener listener = new InteractiveScriptStateListener();

        System.out.println("\n***Executing scriptSig***\n");
        Script script = scriptSig;
        Script.executeDebugScript(null, 0, script, stack, Coin.ZERO, Script.ALL_VERIFY_FLAGS, listener);

        System.out.println("\n***Executing scriptPubKey***\n");
        script = scriptPubKey;
        Script.executeDebugScript(null, 0, script, stack, Coin.ZERO, Script.ALL_VERIFY_FLAGS, listener);


    }

    public InteractiveScriptStateListener() {
        this(false);
    }

    public InteractiveScriptStateListener(boolean pauseForUser) {
        this.pauseForUser = pauseForUser;
    }

    @Override
    public void onBeforeOpCodeExecuted(boolean willExecute) {

        if (getChunkIndex() == 0) {
            fullScriptString = truncateData(String.valueOf(getScript()));
            System.out.println(fullScriptString);
        }

        System.out.println(String.format("\nExecuting %s operation: [%s]", getCurrentChunk().isOpCode() ? "OP_CODE" : "PUSHDATA", ScriptOpCodes.getOpCodeName(getCurrentChunk().opcode)));
    }

    @Override
    public void onAfterOpCodeExectuted() {

        List<ScriptChunk> remaining = getScript().chunks.subList(getChunkIndex(), getScript().chunks.size() - 1);
        Script remainScript = new Script(remaining);
        String remainingString = truncateData(remainScript.toString());
        int startIndex = fullScriptString.indexOf(remainingString);
        String markedScriptString = fullScriptString.substring(0, startIndex) + "^" + fullScriptString.substring(startIndex);
        //System.out.println("Remaining code: " + remainingString);
        System.out.println("Execution point (^): " + markedScriptString);
        System.out.println();

        //dump stacks
        List<byte[]> reverseStack = new ArrayList<byte[]>(getStack());
        Collections.reverse(reverseStack);
        System.out.println("Stack:");

        for (byte[] bytes: reverseStack) {
            System.out.println(HEX.encode(bytes));
        }
        System.out.println();

        if (getAltstack().size() > 0) {
            reverseStack = new ArrayList<byte[]>(getAltstack());
            Collections.reverse(reverseStack);
            System.out.println("Alt Stack:");

            for (byte[] bytes: reverseStack) {
                System.out.println(HEX.encode(bytes));
            }
            System.out.println();
        }

        if (getIfStack().size() > 0) {
            List<Boolean>reverseIfStack = new ArrayList<Boolean>(getIfStack());
            Collections.reverse(reverseIfStack);
            System.out.println("If Stack:");

            for (Boolean element: reverseIfStack) {
                System.out.println(element);
            }
            System.out.println();
        }

        if (pauseForUser) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Press enter key to continue");
            scanner.nextLine();
        }

    }

    @Override
    public void onExceptionThrown(ScriptException exception) {
        System.out.println("Exception thrown: ");
    }

    @Override
    public void onScriptComplete() {

    }

    private String truncateData(String scriptString) {

        Pattern p = Pattern.compile("\\[(.*?)\\]");
        Matcher m = p.matcher(scriptString);

        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String data = m.group(0);
            if (data.length() > 10) {
                data = data.substring(0, 5) + "..." + data.substring(data.length() - 5);
            }
            m.appendReplacement(sb, data);
        }
        m.appendTail(sb);

        return sb.toString();
    }
}
