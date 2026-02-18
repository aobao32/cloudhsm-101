package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * CloudHSMDecryption 单元测试
 */
class CloudHSMDecryptionTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // findKeyByLabel 测试
    // -----------------------------------------------------------------------

    @Test
    void findKeyByLabel_shouldReturnKeyWhenFound() throws Exception {
        KeyStore mockKeyStore = mock(KeyStore.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyStore.getKey("MyAES256Key", null)).thenReturn(mockKey);

        try (MockedStatic<KeyStore> ksStatic = mockStatic(KeyStore.class)) {
            ksStatic.when(() -> KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMDecryption.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            SecretKey result = (SecretKey) method.invoke(null, "MyAES256Key");
            assertNotNull(result);
        }
    }

    @Test
    void findKeyByLabel_shouldThrowWhenKeyNotFound() throws Exception {
        KeyStore mockKeyStore = mock(KeyStore.class);
        when(mockKeyStore.getKey(anyString(), any())).thenReturn(null);

        try (MockedStatic<KeyStore> ksStatic = mockStatic(KeyStore.class)) {
            ksStatic.when(() -> KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMDecryption.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            Exception ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, "MissingKey"));
            assertTrue(ex.getCause().getMessage().contains("MissingKey"));
        }
    }

    // -----------------------------------------------------------------------
    // decryptString 测试
    // -----------------------------------------------------------------------

    @Test
    void decryptString_shouldExtractIvAndDecrypt() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        byte[] expectedPlaintext = "Hello CloudHSM!".getBytes("UTF-8");
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(expectedPlaintext);

        // 构造合法的 combined = IV(12) + ciphertext(16)
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[16];
        byte[] combined = new byte[28];
        System.arraycopy(iv, 0, combined, 0, 12);
        System.arraycopy(ciphertext, 0, combined, 12, 16);
        String base64Input = Base64.getEncoder().encodeToString(combined);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMDecryption.class
                    .getDeclaredMethod("decryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            String result = (String) method.invoke(null, base64Input, mockKey);
            assertEquals("Hello CloudHSM!", result);

            // 验证 Cipher 以 DECRYPT_MODE 初始化，且传入了 GCMParameterSpec
            verify(mockCipher).init(eq(Cipher.DECRYPT_MODE), eq(mockKey), any(GCMParameterSpec.class));
        }
    }

    @Test
    void decryptString_shouldPropagateExceptionOnDecryptFailure() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenThrow(new RuntimeException("GCM tag mismatch"));

        byte[] combined = new byte[28]; // 12 IV + 16 ciphertext
        String base64Input = Base64.getEncoder().encodeToString(combined);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMDecryption.class
                    .getDeclaredMethod("decryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, base64Input, mockKey));
        }
    }
}
