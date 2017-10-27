/*
 * Copyright (c) 2011 - 2013 United ID.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.unitedid.yhsm.internal;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.unitedid.yhsm.SetupCommon;

import static org.testng.Assert.*;

public class AESECBCmdTest extends SetupCommon {
    private int khEncrypt = 4097; // 0x1001
    private int khDecrypt = 4097; // 0x1001
    private int khCompare = 4097; // 0x1001

    @BeforeTest
    public void setUp() throws Exception {
        super.setUp();
    }

    @AfterTest
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void testEncryptAndDecryptBA() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        byte[] plaintext = {(byte)0xbe, (byte)0xef, (byte)0xea, 0x73, 0x12, (byte)0xde, 0x40, 0x10,
                            (byte)0xf1, 0x01, 0x21, (byte)0xa1, 0x40, (byte)0xc0, (byte)0xff, (byte)0xee};
        byte[] cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        assertNotSame(plaintext, cipherText);

        byte[] decrypted = hsm.decryptAES_ECB(cipherText, khDecrypt);
        assertEquals(decrypted, plaintext);
    }

    @Test
    public void testEncryptAndDecrypt() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        String plaintext = "World domination";
        String cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        assertNotSame(plaintext, cipherText);

        String decrypted = hsm.decryptAES_ECB(cipherText, khDecrypt);
        assertEquals(decrypted, plaintext);
    }

    @Test(expectedExceptions = YubiHSMInputException.class,
          expectedExceptionsMessageRegExp = "Argument 'plaintext' is too long, expected max 16 but got 20")
    public void testEncryptInputExceptionBA() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        byte[] tooLong = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff,
                0x70, 0x01, 0x01, 0x46};
        hsm.encryptAES_ECB(tooLong, khEncrypt);
    }

    @Test(expectedExceptions = YubiHSMInputException.class,
          expectedExceptionsMessageRegExp = "Argument 'plaintext' is too long, expected max 16 but got 26")
    public void testEncryptInputException() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        String aTooLongString = "abcdefghijklmonpqrstuvwxyz";
        hsm.encryptAES_ECB(aTooLongString, khEncrypt);
    }

    @Test(expectedExceptions = YubiHSMInputException.class,
          expectedExceptionsMessageRegExp = "Wrong size of argument 'cipherText', expected 16 but got 19")
    public void testDecryptInputExceptionBA() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        byte[] tooLong = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff,
                          0x10, 0x07, (byte)0x66};
        hsm.decryptAES_ECB(tooLong, khDecrypt);
    }

    @Test(expectedExceptions = YubiHSMInputException.class,
          expectedExceptionsMessageRegExp = "Wrong size of argument 'cipherText', expected 16 but got 19")
    public void testDecryptInputException() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        String aTooLongCipher = "112233445566778899aaccddeeff1122334455";
        hsm.decryptAES_ECB(aTooLongCipher, khDecrypt);
    }

    @Test
    public void testCompareBA() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        byte[] plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        byte[] cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        assertTrue(hsm.compareAES_ECB(khCompare, cipherText, plaintext));
    }

    @Test
    public void testCompareNotOkBA() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        byte[] plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        byte[] cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        plaintext[0] = (byte)0xff;
        assertFalse(hsm.compareAES_ECB(khCompare, cipherText, plaintext));
    }

    @Test
    public void testCompare() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        String plaintext = "Good deal";
        String cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        assertTrue(hsm.compareAES_ECB(khCompare, cipherText, plaintext));
    }

    @Test
    public void testCompareNotOk() throws YubiHSMCommandFailedException, YubiHSMErrorException, YubiHSMInputException {
        String plaintext = "Good deal";
        String cipherText = hsm.encryptAES_ECB(plaintext, khEncrypt);
        assertFalse(hsm.compareAES_ECB(khCompare, cipherText, plaintext.substring(0,5)));
    }
}
