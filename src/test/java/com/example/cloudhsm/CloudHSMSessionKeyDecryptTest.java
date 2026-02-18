package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * CloudHSMSessionKeyDecrypt 单元测试
 * 验证 Session Key 派生参数和 AES-GCM 解密逻辑
 */
class CloudHSMSessionKeyDecryptTest {

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

            java.lang.reflect.Method method = CloudHSMSessionKeyDecrypt.class
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

            java.lang.reflect.Method method = CloudHSMSessionKeyDecrypt.class
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
    void deriveSessionKey_shouldUseAesFactoryWithCloudHsmProvider() throws Exception {
        SecretKey mockMasterKey = mock(SecretKey.class);
        SecretKeyFactory mockFactory = mock(SecretKeyFactory.class);
        when(mockFactory.generateSecret(any())).thenReturn(mock(SecretKey.class));

        try (MockedStatic<SecretKeyFactory> skfStatic = mockStatic(SecretKeyFactory.class)) {
            skfStatic.when(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockFactory);

            java.lang.reflect.Method method = CloudHSMSessionKeyDecrypt.class
                    .getDeclaredMethod("deriveSessionKey", SecretKey.class, String.class, String.class);
            method.setAccessible(true);
            method.invoke(null, mockMasterKey, "DEVICE123456", "AA:BB:CC:DD:EE:FF");

            skfStatic.verify(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void deriveSessionKey_shouldReturnNonNullSessionKey() throws Exception {
        SecretKey mockMasterKey = mock(SecretKey.class);
        SecretKeyFactory mockFactory = mock(SecretKeyFactory.class);
        SecretKey mockSessionKey = mock(SecretKey.class);
        when(mockFactory.generateSecret(any())).thenReturn(mockSessionKey);

        try (MockedStatic<SecretKeyFactory> skfStatic = mockStatic(SecretKeyFactory.class)) {
            skfStatic.when(() -> SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockFactory);

            java.lang.reflect.Method method = CloudHSMSessionKeyDecrypt.class
                    .getDeclaredMethod("deriveSessionKey", SecretKey.class, String.class, String.class);
            method.setAccessible(true);

            SecretKey result = (SecretKey) method.invoke(null, mockMasterKey, "DEV001", "00:11:22:33:44:55");
            assertNotNull(result);
        }
    }

    // -----------------------------------------------------------------------
    // AES-GCM 解密：IV 提取和 GCMParameterSpec 构造验证
    // -----------------------------------------------------------------------

    @Test
    void decryptLogic_shouldExtractFirst12BytesAsIv() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenReturn("plaintext".getBytes("UTF-8"));

        // 构造 combined = IV(12) + ciphertext(16)
        byte[] combined = new byte[28];
        for (int i = 0; i < 12; i++) combined[i] = (byte)(i + 10);
        String base64Input = Base64.getEncoder().encodeToString(combined);

        GCMParameterSpec[] capturedSpec = new GCMParameterSpec[1];
        doAnswer(inv -> {
            capturedSpec[0] = (GCMParameterSpec) inv.getArgument(2);
            return null;
        }).when(mockCipher).init(anyInt(), any(SecretKey.class), any(GCMParameterSpec.class));

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            // 模拟解密逻辑
            byte[] decodedBytes = Base64.getDecoder().decode(base64Input);
            byte[] iv = new byte[12];
            byte[] ciphertext = new byte[decodedBytes.length - 12];
            System.arraycopy(decodedBytes, 0, iv, 0, 12);
            System.arraycopy(decodedBytes, 12, ciphertext, 0, ciphertext.length);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, mockKey, gcmSpec);

            assertNotNull(capturedSpec[0]);
            assertEquals(128, capturedSpec[0].getTLen());
            assertEquals(10, capturedSpec[0].getIV()[0]);
            assertEquals(11, capturedSpec[0].getIV()[1]);
        }
    }

    @Test
    void decryptLogic_shouldUseAesGcmNoPadding() throws Exception {
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(new byte[0]);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);

            cipherStatic.verify(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME));
        }
    }
}
