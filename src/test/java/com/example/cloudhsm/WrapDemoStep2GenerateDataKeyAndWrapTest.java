package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * WrapDemoStep2GenerateDataKeyAndWrap 单元测试
 */
class WrapDemoStep2GenerateDataKeyAndWrapTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // createDataKey 测试
    // -----------------------------------------------------------------------

    @Test
    void createDataKey_shouldSetWrapWithTrustedAndExtractableTrue() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyGen.generateKey()).thenReturn(mockKey);

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(0);
            return null;
        }).when(mockKeyGen).init(any(KeyAttributesMap.class));

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            SecretKey result = WrapDemoStep2GenerateDataKeyAndWrap.createDataKey("temp-data-key");

            assertNotNull(result);
            assertNotNull(capturedSpec[0]);
            // Data Key 核心约束：WRAP_WITH_TRUSTED=true, EXTRACTABLE=true, TOKEN=false
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.WRAP_WITH_TRUSTED),
                    "Data Key 必须设置 WRAP_WITH_TRUSTED=true");
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE),
                    "Data Key 必须可导出以便 wrap");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.TOKEN),
                    "Data Key 是 session key，TOKEN=false");
            assertEquals(256, capturedSpec[0].get(KeyAttribute.SIZE));
        }
    }

    @Test
    void createDataKey_shouldUseLabelFromParameter() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        when(mockKeyGen.generateKey()).thenReturn(mock(SecretKey.class));

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(0);
            return null;
        }).when(mockKeyGen).init(any(KeyAttributesMap.class));

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            WrapDemoStep2GenerateDataKeyAndWrap.createDataKey("my-data-key");

            assertEquals("my-data-key", capturedSpec[0].get(KeyAttribute.LABEL));
        }
    }

    // -----------------------------------------------------------------------
    // findKeyByLabel 测试
    // -----------------------------------------------------------------------

    @Test
    void findKeyByLabel_shouldReturnKeyWhenFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyStore.getKey(any(KeyAttributesMap.class))).thenReturn(mockKey);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            SecretKey result = WrapDemoStep2GenerateDataKeyAndWrap.findKeyByLabel("new-master-key");
            assertNotNull(result);
        }
    }

    @Test
    void findKeyByLabel_shouldReturnNullWhenKeyNotFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyAttributesMap.class))).thenReturn(null);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            SecretKey result = WrapDemoStep2GenerateDataKeyAndWrap.findKeyByLabel("missing-key");
            assertNull(result);
        }
    }

    // -----------------------------------------------------------------------
    // wrapKey 测试
    // -----------------------------------------------------------------------

    @Test
    void wrapKey_shouldUseAesWrapEcbNoPadding() throws Exception {
        SecretKey mockKeyToWrap = mock(SecretKey.class);
        SecretKey mockWrappingKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        byte[] fakeWrappedKey = new byte[]{1, 2, 3, 4};
        when(mockCipher.wrap(mockKeyToWrap)).thenReturn(fakeWrappedKey);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            byte[] result = WrapDemoStep2GenerateDataKeyAndWrap.wrapKey(mockKeyToWrap, mockWrappingKey);

            assertArrayEquals(fakeWrappedKey, result);
            cipherStatic.verify(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void wrapKey_shouldInitCipherWithWrapMode() throws Exception {
        SecretKey mockKeyToWrap = mock(SecretKey.class);
        SecretKey mockWrappingKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.wrap(any())).thenReturn(new byte[8]);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            WrapDemoStep2GenerateDataKeyAndWrap.wrapKey(mockKeyToWrap, mockWrappingKey);

            verify(mockCipher).init(Cipher.WRAP_MODE, mockWrappingKey);
        }
    }

    @Test
    void wrapKey_shouldPropagateExceptionOnFailure() throws Exception {
        SecretKey mockKeyToWrap = mock(SecretKey.class);
        SecretKey mockWrappingKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.wrap(any())).thenThrow(new RuntimeException("Wrap failed"));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            assertThrows(Exception.class,
                    () -> WrapDemoStep2GenerateDataKeyAndWrap.wrapKey(mockKeyToWrap, mockWrappingKey));
        }
    }
}
