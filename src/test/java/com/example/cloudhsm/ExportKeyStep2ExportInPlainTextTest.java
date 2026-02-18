package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyReferenceSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.nio.file.Path;
import java.security.Key;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * ExportKeyStep2ExportInPlainText 单元测试
 */
class ExportKeyStep2ExportInPlainTextTest {

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
        Key mockKey = mock(Key.class);
        when(mockKeyStore.getKey(any(KeyReferenceSpec.class))).thenReturn(mockKey);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            Key result = ExportKeyStep2ExportInPlainText.findKeyByHandle(0x2fddL);
            assertNotNull(result);
        }
    }

    @Test
    void findKeyByHandle_shouldReturnNullWhenKeyNotFound() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyReferenceSpec.class))).thenReturn(null);

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            Key result = ExportKeyStep2ExportInPlainText.findKeyByHandle(0xDEADL);
            assertNull(result);
        }
    }

    @Test
    void findKeyByHandle_shouldUseKeyReferenceSpec() throws Exception {
        KeyStoreWithAttributes mockKeyStore = mock(KeyStoreWithAttributes.class);
        when(mockKeyStore.getKey(any(KeyReferenceSpec.class))).thenReturn(mock(Key.class));

        try (MockedStatic<KeyStoreWithAttributes> ksStatic = mockStatic(KeyStoreWithAttributes.class)) {
            ksStatic.when(() -> KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyStore);

            ExportKeyStep2ExportInPlainText.findKeyByHandle(0x1234L);

            // 验证通过 KeyReferenceSpec 查找密钥
            verify(mockKeyStore).getKey(any(KeyReferenceSpec.class));
        }
    }

    // -----------------------------------------------------------------------
    // saveToPEM 测试（通过反射）
    // -----------------------------------------------------------------------

    @Test
    void saveToPEM_shouldWritePemFileWithCorrectHeaders(@TempDir Path tempDir) throws Exception {
        java.lang.reflect.Method method = ExportKeyStep2ExportInPlainText.class
                .getDeclaredMethod("saveToPEM", byte[].class, String.class);
        method.setAccessible(true);

        byte[] keyBytes = new byte[32];
        Path pemFile = tempDir.resolve("test.pem");
        method.invoke(null, keyBytes, pemFile.toString());

        String content = new String(java.nio.file.Files.readAllBytes(pemFile));
        assertTrue(content.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(content.contains("-----END PRIVATE KEY-----"));
    }

    @Test
    void saveToPEM_shouldContainBase64EncodedKey(@TempDir Path tempDir) throws Exception {
        java.lang.reflect.Method method = ExportKeyStep2ExportInPlainText.class
                .getDeclaredMethod("saveToPEM", byte[].class, String.class);
        method.setAccessible(true);

        byte[] keyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        Path pemFile = tempDir.resolve("key.pem");
        method.invoke(null, keyBytes, pemFile.toString());

        String content = new String(java.nio.file.Files.readAllBytes(pemFile));
        String expectedBase64 = Base64.getEncoder().encodeToString(keyBytes);
        // MIME encoder 每64字符换行，去掉换行后比较
        assertTrue(content.replace("\n", "").contains(expectedBase64.replace("\n", "")));
    }

    // -----------------------------------------------------------------------
    // bytesToHex 测试（通过反射）
    // -----------------------------------------------------------------------

    @Test
    void bytesToHex_shouldConvertCorrectly() throws Exception {
        java.lang.reflect.Method method = ExportKeyStep2ExportInPlainText.class
                .getDeclaredMethod("bytesToHex", byte[].class);
        method.setAccessible(true);

        String result = (String) method.invoke(null, new byte[]{(byte) 0xAB, 0x0C, (byte) 0xFF});
        assertEquals("ab0cff", result);
    }
}
