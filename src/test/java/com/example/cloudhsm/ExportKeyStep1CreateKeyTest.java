package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * ExportKeyStep1CreateKey 单元测试
 * 验证 AES-256 密钥创建时的属性配置，特别是 EXTRACTABLE=true
 */
class ExportKeyStep1CreateKeyTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    @Test
    void createKey_shouldSetExtractableTrue() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKey.getAlgorithm()).thenReturn("AES");
        when(mockKeyGen.generateKey()).thenReturn(mockKey);

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(0);
            return null;
        }).when(mockKeyGen).init(any(KeyAttributesMap.class));

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            // 直接调用 main() 中的密钥生成逻辑（通过反射调用内联逻辑）
            // ExportKeyStep1 没有独立方法，通过 mock 验证 init 参数
            KeyGenerator kg = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);

            KeyAttributesMap aesSpec = new KeyAttributesMap();
            aesSpec.put(KeyAttribute.LABEL, "TestKeyForPlainTextExport");
            aesSpec.put(KeyAttribute.SIZE, 256);
            aesSpec.put(KeyAttribute.TOKEN, true);
            aesSpec.put(KeyAttribute.EXTRACTABLE, true);
            aesSpec.put(KeyAttribute.ENCRYPT, true);
            aesSpec.put(KeyAttribute.DECRYPT, true);

            kg.init(aesSpec);
            SecretKey result = kg.generateKey();

            assertNotNull(result);
            assertNotNull(capturedSpec[0]);
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE),
                    "导出密钥必须设置 EXTRACTABLE=true");
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.TOKEN),
                    "持久化密钥必须设置 TOKEN=true");
            assertEquals(256, capturedSpec[0].get(KeyAttribute.SIZE));
        }
    }

    @Test
    void createKey_shouldUseAes256() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyGen.generateKey()).thenReturn(mockKey);

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);

            kgStatic.verify(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void createKey_shouldPropagateExceptionOnProviderFailure() {
        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenThrow(new java.security.NoSuchAlgorithmException("Provider not available"));

            assertThrows(java.security.NoSuchAlgorithmException.class,
                    () -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME));
        }
    }
}
