/*
 * elomagic Core (Java 11)
 * Copyright (c) 2017-present Carsten Rambow
 * mailto:developer AT elomagic DOT de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.elomagic.spps.jshiro;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class SimpleCryptTest {

    public SimpleCryptTest() {
    }

    @Test
    void testEncryptDecrypt() throws Exception {
        System.out.println("encrypt");

        String value = "secret";

        String encrypted = SimpleCrypt.encrypt(value);

        Assertions.assertNotEquals(value, encrypted);

        String decrypted = SimpleCrypt.decrypt(encrypted);

        Assertions.assertEquals(value, decrypted);
    }

    /**
     * Test of isEncryptedValue method, of class SimpleCrypt.
     */
    @Test
    void testIsEncryptedValue() {
        System.out.println("isEncryptedValue");
        String value = "";

        Assertions.assertTrue(SimpleCrypt.isEncryptedValue("{abc}"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("abc}"));
    }

    @Test
    void testDecrypt1() throws Exception {
        IOException ex = Assertions.assertThrows(IOException.class, ()->SimpleCrypt.decrypt("this isn't a encapsulated value"));
        Assertions.assertTrue(ex.getMessage().contains("This value is not encapsu"));
    }

}
