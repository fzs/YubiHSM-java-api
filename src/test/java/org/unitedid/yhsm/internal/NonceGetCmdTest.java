/*
 * Copyright (c) 2011 United ID. All rights reserved.
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
 *
 * @author Stefan Wold <stefan.wold@unitedid.org>
 */

package org.unitedid.yhsm.internal;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.unitedid.yhsm.SetupCommon;

import static junit.framework.Assert.assertEquals;

public class NonceGetCmdTest extends SetupCommon {

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void testNonceGet() throws YubiHSMErrorException, YubiHSMCommandFailedException {
        Nonce nonce1 = hsm.getNonce((short) 1);
        Nonce nonce2 = hsm.getNonce((short) 1);
        assertEquals(nonce1.getNonceInt() + 1, nonce2.getNonceInt());

        Nonce nonce3 = hsm.getNonce((short) 9);
        assertEquals(nonce2.getNonceInt() +1, nonce3.getNonceInt());

        Nonce nonce4 = hsm.getNonce((short) 1);
        assertEquals(nonce3.getNonceInt() + 9, nonce4.getNonceInt());

        Nonce nonce5 = hsm.getNonce((short) 0);
        Nonce nonce6 = hsm.getNonce((short) 0);
        assertEquals(nonce5.getNonceInt(), nonce6.getNonceInt());
    }
}