package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyReferenceSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * CloudHSMEncryptionByKeyRefID 单元测试
 */
class CloudHSMEncryptionByKeyRefIDTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // findKeyByHandle 测试
    // -----------------------------------------------------------------------

    @Test
    void findKeyByHandle_shouldReturnKeyWhenFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyStore.getKey(any(KeyReferenceSpec.class))).thenReturn(mockKey);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMEncryptionByKeyRefID.class
                    .getDeclaredMethod("findKeyByHandle", long.class);
            method.setAccessible(true);

            SecretKey result = (SecretKey) method.invoke(null, 0x11b6L);
            assertNotNull(result);
        }
    }

    @Test
    void findKeyByHandle_shouldThrowWhenKeyNotFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyReferenceSpec.class))).thenReturn(null);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            java.lang.reflect.Method method = CloudHSMEncryptionByKeyRefID.class
                    .getDeclaredMethod("findKeyByHandle", long.class);
            method.setAccessible(true);

            Exception ex = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(null, 0xDEADL));
            assertTrue(ex.getCause().getMessage().contains("dead"));
        }
    }

    // -----------------------------------------------------------------------
    // encryptString 测试
    // -----------------------------------------------------------------------

    @Test
    void encryptString_shouldReturnBase64WithIvPrepended() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);

        byte[] fakeIv = new byte[12];
        byte[] fakeCiphertext = new byte[]{10, 20, 30};
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(fakeCiphertext);
        when(mockCipher.getIV()).thenReturn(fakeIv);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMEncryptionByKeyRefID.class
                    .getDeclaredMethod("encryptString", String.class, SecretKey.class);
            method.setAccessible(true);

            String result = (String) method.invoke(null, "plaintext", mockKey);
            byte[] decoded = Base64.getDecoder().decode(result);
            assertEquals(fakeIv.length + fakeCiphertext.length, decoded.length);
        }
    }

    @Test
    void encryptString_shouldUseAesGcmNoPadding() throws Exception {
        SecretKey mockKey = mock(SecretKey.class);
        Cipher mockCipher = mock(Cipher.class);
        when(mockCipher.doFinal(any(byte[].class))).thenReturn(new byte[0]);
        when(mockCipher.getIV()).thenReturn(new byte[12]);

        try (MockedStatic<Cipher> cipherStatic = mockStatic(Cipher.class)) {
            cipherStatic.when(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockCipher);

            java.lang.reflect.Method method = CloudHSMEncryptionByKeyRefID.class
                    .getDeclaredMethod("encryptString", String.class, SecretKey.class);
            method.setAccessible(true);
            method.invoke(null, "test", mockKey);

            cipherStatic.verify(() -> Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME));
        }
    }
}
