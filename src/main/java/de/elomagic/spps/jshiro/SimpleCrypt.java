/*
 * Simple Password Protection Solution with Apache Shiro
 *
 * Copyright © 2021-present Carsten Rambow (hl7inspector.dev@elomagic.de)
 *
 * This file is part of Simple Password Protection Solution with Apache Shiro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.elomagic.spps.jshiro;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.apache.shiro.util.ByteSource;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Collections;

/**
 * Helper class to en-/decrypt of passwords.
 *
 * @author Carsten Rambow
 */
public final class SimpleCrypt {

    private static final Logger LOGGER = LogManager.getLogger(SimpleCrypt.class);
    private static final Path MASTERKEY_FILE = Paths.get(System.getProperty("user.home"), ".elomagic", "masterkey");
    private static final DefaultBlockCipherService CIPHER = new AesCipherService();

    private SimpleCrypt() {
    }

    private static byte[] getMasterKey() throws IOException {

        if(!MASTERKEY_FILE.getParent().toFile().exists()) {
            Files.createDirectories(MASTERKEY_FILE.getParent());
        }

        byte[] result;

        if(MASTERKEY_FILE.toFile().exists()) {
            byte[] base64 = Files.readAllBytes(MASTERKEY_FILE);
            result = Base64.decode(base64);
        } else {
            Key key = CIPHER.generateNewKey();
            result = key.getEncoded();

            String base64 = Base64.encodeToString(result);

            Files.write(MASTERKEY_FILE, Collections.singleton(base64), StandardOpenOption.CREATE_NEW);
        }

        return result;
    }


    /**
     * Encrypt, encoded as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted byte array
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable byte[] decrypted) throws GeneralSecurityException {
        if (decrypted == null) {
            return null;
        }

        try {
            ByteSource encrypted = CIPHER.encrypt(decrypted, getMasterKey());

            return "{" + encrypted.toBase64() + "}";
        } catch(Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

    /**
     * Encrypt, encoded as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted char array
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable char[] decrypted) throws GeneralSecurityException {
        return decrypted == null ? null : encrypt(new String(decrypted).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encrypt, encoded as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted string
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable String decrypted) throws GeneralSecurityException {
        return decrypted == null ? null : encrypt(decrypted.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static byte[] decrypt(@Nullable String encryptedBase64) throws GeneralSecurityException {
        if (encryptedBase64 == null) {
            return null;
        }

        if(!isEncryptedValue(encryptedBase64)) {
            throw new GeneralSecurityException("This value is not with curly brackets encapsulated as an encrypted value. Unable to decrypt.");
        }

        try {

            byte[] encryptedBytes = Base64.decode(encryptedBase64.substring(1, encryptedBase64.length() - 1));

            ByteSource decrypted = CIPHER.decrypt(encryptedBytes, getMasterKey());

            return decrypted.getBytes();
        } catch(Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to decrypt data.", ex);
        }
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as char array.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static char[] decryptToChars(@Nullable String encryptedBase64) throws GeneralSecurityException {
        return encryptedBase64 == null ? null : CodecSupport.toChars(decrypt(encryptedBase64));
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static String decryptToString(@Nullable String encryptedBase64) throws GeneralSecurityException {
        return encryptedBase64 == null ? null : new String(decrypt(encryptedBase64), StandardCharsets.UTF_8);
    }

    /**
     * Returns true when value is encrypted, tagged by surrounding braces "{" and "}".
     *
     * @param value Value to be checked
     * @return Returns true when value is identified as an encrypted value.
     */
    public static boolean isEncryptedValue(@Nullable String value) {
        return value != null && value.startsWith("{") && value.endsWith("}");
    }

    /**
     * Tooling method for simple and fast encrypting secrets.
     *
     * @param args First argument must contain value to encrypt
     */
    public static void main(String[] args) {
        try {
            if (args == null || args.length == 0) {
                LOGGER.error("No value found to encrypt.");
                return;
            }

            String s = encrypt(args[0]);

            LOGGER.info("Encrypted value: {}", s);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
        }
    }

}
