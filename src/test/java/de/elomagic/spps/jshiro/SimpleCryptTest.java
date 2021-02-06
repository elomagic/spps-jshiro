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

import org.apache.shiro.codec.CodecSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class SimpleCryptTest {

    @Test
    void testEncryptDecryptWithString() throws Exception {
        String value = "secret";

        String encrypted = SimpleCrypt.encrypt(value);

        Assertions.assertNotEquals(value, encrypted);
        Assertions.assertEquals(54, encrypted.length());

        String decrypted = SimpleCrypt.decryptToString(encrypted);

        Assertions.assertEquals(value, decrypted);

        String e1 = SimpleCrypt.encrypt(value);
        String e2 = SimpleCrypt.encrypt(value);
        Assertions.assertNotEquals(e1, e2);

        Assertions.assertThrows(GeneralSecurityException.class, () -> SimpleCrypt.decryptToString("{bullshit}"));
    }

    @Test
    void testEncryptDecryptWithChars() throws Exception {
        String value = "secretäöüß";

        char[] chars = CodecSupport.toChars(value.getBytes(StandardCharsets.UTF_8));

        String encrypted = SimpleCrypt.encrypt(chars);

        Assertions.assertNotEquals(value, encrypted);

        char[] decryptedChars = SimpleCrypt.decryptToChars(encrypted);

        Assertions.assertArrayEquals(chars, decryptedChars);

        Assertions.assertNull(SimpleCrypt.encrypt((String)null));
        Assertions.assertNull(SimpleCrypt.encrypt((byte[])null));
        Assertions.assertNull(SimpleCrypt.decryptToString(null));
        Assertions.assertNull(SimpleCrypt.decrypt(null));
    }

    @Test
    void testMain() {
        Assertions.assertDoesNotThrow(() -> SimpleCrypt.main(new String[] {"abcde"}));
        Assertions.assertDoesNotThrow(() -> SimpleCrypt.main(null));
    }

    @Test
    void testIsEncryptedValue() {
        Assertions.assertTrue(SimpleCrypt.isEncryptedValue("{abc}"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("abc}"));
    }

    @Test
    void testDecrypt1() {
        Exception ex = Assertions.assertThrows(GeneralSecurityException.class, ()->SimpleCrypt.decrypt("this isn't a encapsulated value"));
        Assertions.assertTrue(ex.getMessage().contains("This value is not with curly brackets"));
    }

}
