package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * CloudHSMKeyDerivation 单元测试
 */
class CloudHSMKeyDerivationTest {

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

            java.lang.reflect.Method method = CloudHSMKeyDerivation.class
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

            java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                    .getDeclaredMethod("findKeyByLabel", String.class);
            method.setAccessible(true);

            Exception ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, "NoSuchKey"));
            assertTrue(ex.getCause().getMessage().contains("NoSuchKey"));
        }
    }

    // -----------------------------------------------------------------------
    // hkdfSha384 测试
    // -----------------------------------------------------------------------

    @Test
    void hkdfSha384_shouldReturnRequestedLength() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Mac mockMac = mock(Mac.class);
        // SHA-384 输出 48 字节
        byte[] fakeHash = new byte[48];
        for (int i = 0; i < 48; i++) fakeHash[i] = (byte) i;
        when(mockMac.doFinal()).thenReturn(fakeHash);

        try (MockedStatic<Mac> macStatic = mockStatic(Mac.class)) {
            macStatic.when(() -> Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockMac);

            java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                    .getDeclaredMethod("hkdfSha384", SecretKey.class, byte[].class, byte[].class, int.class);
            method.setAccessible(true);

            byte[] result = (byte[]) method.invoke(null, mockKey, null, "info".getBytes(), 32);
            assertEquals(32, result.length);
        }
    }

    @Test
    void hkdfSha384_shouldTruncateToRequestedLength() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Mac mockMac = mock(Mac.class);
        byte[] fakeHash = new byte[48];
        for (int i = 0; i < 48; i++) fakeHash[i] = (byte)(i + 1);
        when(mockMac.doFinal()).thenReturn(fakeHash);

        try (MockedStatic<Mac> macStatic = mockStatic(Mac.class)) {
            macStatic.when(() -> Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockMac);

            java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                    .getDeclaredMethod("hkdfSha384", SecretKey.class, byte[].class, byte[].class, int.class);
            method.setAccessible(true);

            byte[] result = (byte[]) method.invoke(null, mockKey, null, new byte[0], 16);
            assertEquals(16, result.length);
            // 验证前16字节与 fakeHash 一致
            for (int i = 0; i < 16; i++) {
                assertEquals(fakeHash[i], result[i]);
            }
        }
    }

    @Test
    void hkdfSha384_shouldUseHmacSha384WithCloudHsmProvider() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Mac mockMac = mock(Mac.class);
        when(mockMac.doFinal()).thenReturn(new byte[48]);

        try (MockedStatic<Mac> macStatic = mockStatic(Mac.class)) {
            macStatic.when(() -> Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockMac);

            java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                    .getDeclaredMethod("hkdfSha384", SecretKey.class, byte[].class, byte[].class, int.class);
            method.setAccessible(true);
            method.invoke(null, mockKey, null, new byte[0], 32);

            macStatic.verify(() -> Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    // -----------------------------------------------------------------------
    // bytesToHex 测试
    // -----------------------------------------------------------------------

    @Test
    void bytesToHex_shouldConvertCorrectly() throws Exception {
        java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                .getDeclaredMethod("bytesToHex", byte[].class);
        method.setAccessible(true);

        String result = (String) method.invoke(null, new byte[]{0x0A, (byte) 0xFF, 0x00, 0x1B});
        assertEquals("0aff001b", result);
    }

    @Test
    void bytesToHex_shouldReturnEmptyStringForEmptyInput() throws Exception {
        java.lang.reflect.Method method = CloudHSMKeyDerivation.class
                .getDeclaredMethod("bytesToHex", byte[].class);
        method.setAccessible(true);

        String result = (String) method.invoke(null, new byte[0]);
        assertEquals("", result);
    }
}
