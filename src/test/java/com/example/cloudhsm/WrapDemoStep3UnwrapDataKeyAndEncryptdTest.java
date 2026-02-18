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
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * WrapDemoStep3UnwrapDataKeyAndEncryptd 单元测试
 */
class WrapDemoStep3UnwrapDataKeyAndEncryptdTest {

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

            SecretKey result = WrapDemoStep3UnwrapDataKeyAndEncryptd.findKeyByLabel("new-master-key");
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

            SecretKey result = WrapDemoStep3UnwrapDataKeyAndEncryptd.findKeyByLabel("missing");
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
        SecretKey mockDataKey = mock(SecretKey.class);
        when(mockCipher.unwrap(any(byte[].class), eq("AES"), eq(Cipher.SECRET_KEY)))
                .thenReturn(mockDataKey);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            SecretKey result = WrapDemoStep3UnwrapDataKeyAndEncryptd.unwrapKey(
                    new byte[40], mockUnwrappingKey);

            assertNotNull(result);
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

            WrapDemoStep3UnwrapDataKeyAndEncryptd.unwrapKey(new byte[40], mockUnwrappingKey);

            assertNotNull(capturedSpec[0]);
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.TOKEN),
                    "Unwrap 的 Data Key 是 session key，TOKEN=false");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE),
                    "Unwrap 的 Data Key 不可导出");
        }
    }

    // -----------------------------------------------------------------------
    // encryptMessage 测试
    // -----------------------------------------------------------------------

    @Test
    void encryptMessage_shouldReturnBase64WithIvPrepended() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        byte[] fakeIv = new byte[12];
        byte[] fakeCiphertext = new byte[]{5, 6, 7, 8};
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(fakeCiphertext);
        when(mockCipher.getIV()).thenReturn(fakeIv);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            String result = WrapDemoStep3UnwrapDataKeyAndEncryptd.encryptMessage("hello", mockKey);

            assertNotNull(result);
            byte[] decoded = Base64.getDecoder().decode(result);
            assertEquals(fakeIv.length + fakeCiphertext.length, decoded.length);
        }
    }

    @Test
    void encryptMessage_shouldInitCipherWithEncryptMode() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(new byte[0]);
        when(mockCipher.getIV()).thenReturn(new byte[12]);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            WrapDemoStep3UnwrapDataKeyAndEncryptd.encryptMessage("test", mockKey);

            verify(mockCipher).init(Cipher.ENCRYPT_MODE, mockKey);
        }
    }
}
