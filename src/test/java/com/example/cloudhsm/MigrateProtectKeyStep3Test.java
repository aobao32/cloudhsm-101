package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * MigrateProtectKeyStep3 单元测试
 */
class MigrateProtectKeyStep3Test {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // findPrivateKeyByLabel 测试
    // -----------------------------------------------------------------------

    @Test
    void findPrivateKeyByLabel_shouldReturnKeyWhenFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        PrivateKey mockKey = mock(PrivateKey.class);
        when(mockKeyStore.getKey(any(KeyAttributesMap.class))).thenReturn(mockKey);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            PrivateKey result = MigrateProtectKeyStep3.findPrivateKeyByLabel("migration-key-private");
            assertNotNull(result);
        }
    }

    @Test
    void findPrivateKeyByLabel_shouldReturnNullWhenKeyNotFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyAttributesMap.class))).thenReturn(null);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            PrivateKey result = MigrateProtectKeyStep3.findPrivateKeyByLabel("nonexistent-key");
            assertNull(result);
        }
    }

    @Test
    void findPrivateKeyByLabel_shouldSearchByLabelAttribute() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyAttributesMap.class))).thenReturn(mock(PrivateKey.class));

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(0);
            return mock(PrivateKey.class);
        }).when(mockKeyStore).getKey(any(KeyAttributesMap.class));

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            MigrateProtectKeyStep3.findPrivateKeyByLabel("migration-key-private");

            assertNotNull(capturedSpec[0]);
            assertEquals("migration-key-private", capturedSpec[0].get(KeyAttribute.LABEL));
        }
    }

    // -----------------------------------------------------------------------
    // unwrapECPrivateKey 测试
    // -----------------------------------------------------------------------

    @Test
    void unwrapECPrivateKey_shouldUseRsaOaepSha512() throws Exception {
        PrivateKey mockUnwrappingKey = mock(PrivateKey.class);
        Cipher mockCipher = mock(Cipher.class);
        PrivateKey mockImportedKey = mock(PrivateKey.class);
        when(mockCipher.unwrap(any(byte[].class), eq("EC"), eq(Cipher.PRIVATE_KEY)))
                .thenReturn(mockImportedKey);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            PrivateKey result = MigrateProtectKeyStep3.unwrapECPrivateKey(
                    new byte[512], mockUnwrappingKey);

            assertNotNull(result);
            cipherStatic.verify(() -> Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void unwrapECPrivateKey_shouldSetTokenAndSignAttributes() throws Exception {
        PrivateKey mockUnwrappingKey = mock(PrivateKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.unwrap(any(byte[].class), anyString(), anyInt()))
                .thenReturn(mock(PrivateKey.class));

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(2);
            return null;
        }).when(mockCipher).init(eq(Cipher.UNWRAP_MODE), eq(mockUnwrappingKey), any(KeyAttributesMap.class));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            MigrateProtectKeyStep3.unwrapECPrivateKey(new byte[512], mockUnwrappingKey);

            assertNotNull(capturedSpec[0]);
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.TOKEN),
                    "导入的密钥必须是持久化密钥 TOKEN=true");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE),
                    "导入的密钥不可导出 EXTRACTABLE=false");
            assertEquals("imported-ec-key", capturedSpec[0].get(KeyAttribute.LABEL));
        }
    }

    @Test
    void unwrapECPrivateKey_shouldPropagateExceptionOnFailure() throws Exception {
        PrivateKey mockUnwrappingKey = mock(PrivateKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.unwrap(any(byte[].class), anyString(), anyInt()))
                .thenThrow(new RuntimeException("Unwrap failed"));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance(
                    "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            assertThrows(Exception.class,
                    () -> MigrateProtectKeyStep3.unwrapECPrivateKey(new byte[512], mockUnwrappingKey));
        }
    }
}
