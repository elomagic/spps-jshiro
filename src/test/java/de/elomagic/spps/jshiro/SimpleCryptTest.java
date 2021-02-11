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

import org.apache.commons.io.FileUtils;
import org.apache.shiro.codec.CodecSupport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Properties;

class SimpleCryptTest {

    private static final String MASTER_KEY_FILENAME = "masterkey";
    private static final Path MASTER_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", MASTER_KEY_FILENAME);

    private static String backup;

    @BeforeAll
    static void beforeAll() throws Exception {
        if (Files.exists(MASTER_KEY_FILE)) {
            backup = FileUtils.readFileToString(MASTER_KEY_FILE.toFile(), StandardCharsets.UTF_8);
        }

        Files.deleteIfExists(MASTER_KEY_FILE);
    }

    @AfterAll
    static void afterAll() throws Exception {
        Files.deleteIfExists(MASTER_KEY_FILE);

        if (backup != null) {
            FileUtils.write(MASTER_KEY_FILE.toFile(), backup, StandardCharsets.UTF_8);
        }
    }

    @Test
    void testCreateMasterKey() throws Exception {
        Assertions.assertTrue(Files.notExists(MASTER_KEY_FILE));

        SimpleCrypt.createMasterKey(true);

        Properties p = new Properties();
        try (Reader reader = Files.newBufferedReader(MASTER_KEY_FILE)) {
            p.load(reader);
        }

        Assertions.assertEquals(2, p.keySet().size());
    }

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
