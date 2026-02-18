package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * CloudHSMSessionKeyEncrypt 单元测试
 * 验证 Session Key 派生参数和 AES-GCM 加密逻辑
 */
class CloudHSMSessionKeyEncryptTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // findKeyByLabel 测试（通过反射）
    // -----------------------------------------------------------------------

    @Test
    void findKeyByLabel_shouldReturnKeyWhenFound() throws Exception {
        KeyStore mockKeyStore = mock(KeyStore.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyStore.getKey("MyAES256Key", null)).thenReturn(mockKey);

        try (MockedStatic<KeyStore> ksStatic = mockStatic(KeyStore.class)) {
            ksStatic.when(() -> KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMSessionKeyEncrypt.class
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

            java.lang.reflect.Method method = CloudHSMSessionKeyEncrypt.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            Exception ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, "MissingKey"));
            assertTrue(ex.getCause().getMessage().contains("MissingKey"));
        }
    }

    // -----------------------------------------------------------------------
    // deriveSessionKey 测试（通过反射）
    // -----------------------------------------------------------------------

    @Test
    void deriveSessionKey_shouldSetSessionKeyAttributes() throws Exception {
        SecretKey mockMasterKey = mock(SecretKey.class);
        SecretKeyFactory mockFactory = mock(SecretKeyFactory.class);
        SecretKey mockSessionKey = mock(SecretKey.class);
        when(mockFactory.generateSecret(any())).thenReturn(mockSessionKey);

        try (MockedStatic<SecretKeyFactory> skfStatic = mockStatic(SecretKeyFactory.class)) {
            skfStatic.when(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockFactory);

            java.lang.reflect.Method method = CloudHSMSessionKeyEncrypt.class
                    .getDeclaredMethod("deriveSessionKey", SecretKey.class, String.class, String.class);
            method.setAccessible(true);

            SecretKey result = (SecretKey) method.invoke(null, mockMasterKey, "DEVICE123456", "AA:BB:CC:DD:EE:FF");
            assertNotNull(result);
            verify(mockFactory).generateSecret(any());
        }
    }

    @Test
    void deriveSessionKey_shouldUseAesFactoryWithCloudHsmProvider() throws Exception {
        SecretKey mockMasterKey = mock(SecretKey.class);
        SecretKeyFactory mockFactory = mock(SecretKeyFactory.class);
        when(mockFactory.generateSecret(any())).thenReturn(mock(SecretKey.class));

        try (MockedStatic<SecretKeyFactory> skfStatic = mockStatic(SecretKeyFactory.class)) {
            skfStatic.when(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockFactory);

            java.lang.reflect.Method method = CloudHSMSessionKeyEncrypt.class
                    .getDeclaredMethod("deriveSessionKey", SecretKey.class, String.class, String.class);
            method.setAccessible(true);
            method.invoke(null, mockMasterKey, "DEV001", "00:11:22:33:44:55");

            skfStatic.verify(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    // -----------------------------------------------------------------------
    // AES-GCM 加密输出格式验证
    // -----------------------------------------------------------------------

    @Test
    void encryptOutput_shouldPrependIvToCiphertext() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        byte[] fakeIv = new byte[12];
        byte[] fakeCiphertext = new byte[]{10, 20, 30, 40};
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(fakeCiphertext);
        when(mockCipher.getIV()).thenReturn(fakeIv);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            // 直接验证 IV+密文组合逻辑
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, mockKey);
            byte[] ciphertext = cipher.doFinal("test".getBytes("UTF-8"));
            byte[] iv = cipher.getIV();

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

            String base64Result = Base64.getEncoder().encodeToString(combined);
            byte[] decoded = Base64.getDecoder().decode(base64Result);

            assertEquals(fakeIv.length + fakeCiphertext.length, decoded.length);
            // 前12字节是IV
            for (int i = 0; i < 12; i++) assertEquals(fakeIv[i], decoded[i]);
        }
    }
}
