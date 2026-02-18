package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * CloudHSMEncryption 单元测试
 * 测试策略：mock KeyStore 和 Cipher 静态工厂，验证参数配置和异常传播
 */
class CloudHSMEncryptionTest {

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

            // 通过反射调用 private 方法
            java.lang.reflect.Method method = CloudHSMEncryption.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            SecretKey result = (SecretKey) method.invoke(null, "MyAES256Key");
            assertNotNull(result);
        }
    }

    @Test
    void findKeyByLabel_shouldThrowWhenKeyNotFound() throws Exception {
        KeyStore mockKeyStore = mock(KeyStore.class);
        when(mockKeyStore.getKey("NonExistentKey", null)).thenReturn(null);

        try (MockedStatic<KeyStore> ksStatic = mockStatic(KeyStore.class)) {
            ksStatic.when(() -> KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMEncryption.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            Exception ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, "NonExistentKey"));
            assertInstanceOf(Exception.class, ex.getCause());
            assertTrue(ex.getCause().getMessage().contains("NonExistentKey"));
        }
    }

    // -----------------------------------------------------------------------
    // encryptString 测试
    // -----------------------------------------------------------------------

    @Test
    void encryptString_shouldReturnBase64EncodedResult() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);

        byte[] fakeIv = new byte[12];
        byte[] fakeCiphertext = "encrypted".getBytes();
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(fakeCiphertext);
        when(mockCipher.getIV()).thenReturn(fakeIv);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMEncryption.class
                    .getDeclaredMethod("encryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            String result = (String) method.invoke(null, "hello", mockKey);
            assertNotNull(result);

            // 验证结果可以被 Base64 解码，且长度 = IV(12) + ciphertext
            byte[] decoded = Base64.getDecoder().decode(result);
            assertEquals(fakeIv.length + fakeCiphertext.length, decoded.length);
        }
    }

    @Test
    void encryptString_shouldPrependIvToCiphertext() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);

        byte[] fakeIv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        byte[] fakeCiphertext = new byte[]{20, 21, 22};
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(fakeCiphertext);
        when(mockCipher.getIV()).thenReturn(fakeIv);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMEncryption.class
                    .getDeclaredMethod("encryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            String result = (String) method.invoke(null, "test", mockKey);
            byte[] decoded = Base64.getDecoder().decode(result);

            // 前12字节是IV
            for (int i = 0; i < 12; i++) {
                assertEquals(fakeIv[i], decoded[i], "IV字节[" + i + "]不匹配");
            }
            // 后续字节是密文
            for (int i = 0; i < fakeCiphertext.length; i++) {
                assertEquals(fakeCiphertext[i], decoded[12 + i], "密文字节[" + i + "]不匹配");
            }
        }
    }

    @Test
    void encryptString_shouldPropagateExceptionOnCipherFailure() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenThrow(new RuntimeException("HSM error"));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMEncryption.class
                    .getDeclaredMethod("encryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, "test", mockKey));
        }
    }
}
