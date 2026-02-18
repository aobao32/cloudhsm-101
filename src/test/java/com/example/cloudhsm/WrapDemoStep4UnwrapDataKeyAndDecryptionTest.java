package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * WrapDemoStep4UnwrapDataKeyAndDecryption 单元测试
 */
class WrapDemoStep4UnwrapDataKeyAndDecryptionTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
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

            SecretKey result = WrapDemoStep4UnwrapDataKeyAndDecryption.findKeyByLabel("new-master-key");
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

            SecretKey result = WrapDemoStep4UnwrapDataKeyAndDecryption.findKeyByLabel("missing");
            assertNull(result);
        }
    }

    // -----------------------------------------------------------------------
    // unwrapKey 测试
    // -----------------------------------------------------------------------

    @Test
    void unwrapKey_shouldUseAesWrapEcbNoPadding() throws Exception {
        SecretKey mockUnwrappingKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.unwrap(any(byte[].class), eq("AES"), eq(Cipher.SECRET_KEY)))
                .thenReturn(mock(SecretKey.class));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            WrapDemoStep4UnwrapDataKeyAndDecryption.unwrapKey(new byte[40], mockUnwrappingKey);

            cipherStatic.verify(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void unwrapKey_shouldSetSessionKeyAttributes() throws Exception {
        SecretKey mockUnwrappingKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.unwrap(any(byte[].class), anyString(), anyInt()))
                .thenReturn(mock(SecretKey.class));

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(2);
            return null;
        }).when(mockCipher).init(eq(Cipher.UNWRAP_MODE), eq(mockUnwrappingKey), any(KeyAttributesMap.class));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            WrapDemoStep4UnwrapDataKeyAndDecryption.unwrapKey(new byte[40], mockUnwrappingKey);

            assertNotNull(capturedSpec[0]);
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.TOKEN));
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE));
            assertEquals("temp-data-key", capturedSpec[0].get(KeyAttribute.LABEL));
        }
    }

    // -----------------------------------------------------------------------
    // decryptMessage 测试
    // -----------------------------------------------------------------------

    @Test
    void decryptMessage_shouldExtractIvAndDecrypt() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        byte[] expectedPlaintext = "Hello CloudHSM!".getBytes("UTF-8");
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(expectedPlaintext);

        // 构造 combined = IV(12) + ciphertext(16)
        byte[] combined = new byte[28];
        String base64Input = Base64.getEncoder().encodeToString(combined);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            String result = WrapDemoStep4UnwrapDataKeyAndDecryption.decryptMessage(base64Input, mockKey);

            assertEquals("Hello CloudHSM!", result);
            verify(mockCipher).init(eq(Cipher.DECRYPT_MODE), eq(mockKey), any(GCMParameterSpec.class));
        }
    }

    @Test
    void decryptMessage_shouldUseFirst12BytesAsIv() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenReturn("plaintext".getBytes());

        // IV 前12字节设置为特定值
        byte[] combined = new byte[28];
        for (int i = 0; i < 12; i++) combined[i] = (byte)(i + 1);
        String base64Input = Base64.getEncoder().encodeToString(combined);

        GCMParameterSpec[] capturedSpec = new GCMParameterSpec[1];
        doAnswer(inv -> {
            capturedSpec[0] = (GCMParameterSpec) inv.getArgument(2);
            return null;
        }).when(mockCipher).init(anyInt(), any(SecretKey.class), any(GCMParameterSpec.class));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            WrapDemoStep4UnwrapDataKeyAndDecryption.decryptMessage(base64Input, mockKey);

            assertNotNull(capturedSpec[0]);
            assertEquals(128, capturedSpec[0].getTLen(), "GCM tag 长度应为 128 bit");
            // 验证 IV 前3字节
            assertEquals(1, capturedSpec[0].getIV()[0]);
            assertEquals(2, capturedSpec[0].getIV()[1]);
            assertEquals(3, capturedSpec[0].getIV()[2]);
        }
    }

    @Test
    void decryptMessage_shouldPropagateExceptionOnDecryptFailure() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenThrow(new RuntimeException("GCM auth failed"));

        byte[] combined = new byte[28];
        String base64Input = Base64.getEncoder().encodeToString(combined);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            assertThrows(Exception.class,
                    () -> WrapDemoStep4UnwrapDataKeyAndDecryption.decryptMessage(base64Input, mockKey));
        }
    }
}
