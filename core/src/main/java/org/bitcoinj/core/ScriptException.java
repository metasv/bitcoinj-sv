/*
 * Copyright 2011 Google Inc.
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


public class ScriptException extends VerificationException {

    public ScriptException(String msg) {
        super(msg);
    }

    public ScriptException(String msg, Exception e) {
        super(msg, e);
    }

    public static class BadOpcodeException extends ScriptException {
        public BadOpcodeException() { super("an illegal opcode is present in the script"); }
    }

    public static class DisabledOpcodeException extends ScriptException {
        public DisabledOpcodeException() { super("script includes a disabled opcode"); }
    }

    public static class DiscourageUpgradableNopsException extends ScriptException {
        public DiscourageUpgradableNopsException() { super("script used a reserved opcode"); }
    }

    public static class DivByZeroException extends ScriptException {
        public DivByZeroException() { super("divide by zero error"); }
    }

    public static class EqualVerifyException extends ScriptException {
        public EqualVerifyException() { super("OP_EQUALVERIFY failed, non-equal operands"); }
    }

    public static class EvalFalseException extends ScriptException {
        public EvalFalseException() { super("script evaluated false"); }
    }

    public static class InvalidAltStackOperationException extends ScriptException {
        public InvalidAltStackOperationException() { super("the operation was invalid given the contents of the altstack"); }
    }

    public static class InvalidNumberRangeException extends ScriptException {
        public InvalidNumberRangeException() { super("operand is not a number in the valid range"); }
    }

    public static class InvalidStackOperationException extends ScriptException {
        /* some possible causes:
         *      - not enough values on the stack for the operation
         */
        public InvalidStackOperationException() { super("the operation was invalid given the contents of the stack"); }
    }

    public static class ModByZeroException extends ScriptException {
        public ModByZeroException() { super("modulo by zero error"); }
    }

    public static class NonStandardScriptException extends ScriptException {
        public NonStandardScriptException() { super("script is not a recognized standard script"); }
    }

    public static class NullDummyException extends ScriptException {
        public NullDummyException() { super("CHECKMULTISIG with non-null nulldummy"); }
    }

    public static class NumEqualVerifyException extends ScriptException {
        public NumEqualVerifyException() { super("OP_NUMEQUALVERIFY failed, non-equal operands"); }
    }

    public static class OpCountException extends ScriptException {
        public OpCountException() { super("script contains too many opcodes"); }
    }

    public static class OperandSizeException extends ScriptException {
        public OperandSizeException() { super("invalid operand size"); }
    }

    public static class OpReturnException extends ScriptException {
        public OpReturnException() { super("the script called OP_RETURN"); }
    }

    public static class OpVerifyFailed extends ScriptException {
        public OpVerifyFailed() { super("the VERIFY failed"); }
    }

    public static class PubKeyCountException extends ScriptException {
        public PubKeyCountException() { super("there are too many, or not enough, public keys"); }
    }

    public static class PushSizeException extends ScriptException {
        /* some possible causes:
         *   - result of OP_CAT would be too large
         *   - result of NUM2BIN would be too large
         */
        public PushSizeException() { super("attempted to push value on the stack that was too large"); }
    }

    public static class ScriptSizeException extends ScriptException {
        public ScriptSizeException() { super("the script is too large"); }
    }

    public static class SigCountException extends ScriptException {
        public SigCountException() { super("sig count out of range"); }
    }

    public static class SigPushOnlyException extends ScriptException {
        public SigPushOnlyException() { super("attempted to spend a P2SH scriptPubKey with a script that contained script ops"); }
    }

    public static class SplitRangeException extends ScriptException {
        public SplitRangeException() { super("invalid OP_SPLIT range"); }
    }

    public static class StackSizeException extends ScriptException {
        public StackSizeException() { super("stack is, or would be, too large"); }
    }

    public static class UnbalancedConditionalException extends ScriptException {
        public UnbalancedConditionalException() { super("the script contains an unbalanced conditional"); }
    }
}
