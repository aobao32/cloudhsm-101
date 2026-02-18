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
 * WrapDemoStep1GenerateMasterKey 单元测试
 * 验证 Master Key 的属性配置：WRAP=true, ENCRYPT=false, EXTRACTABLE=false
 */
class WrapDemoStep1GenerateMasterKeyTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    @Test
    void createMasterKey_shouldSetWrapTrueAndEncryptFalse() throws Exception {
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

            SecretKey result = WrapDemoStep1GenerateMasterKey.createMasterKey("new-master-key");

            assertNotNull(result);
            assertNotNull(capturedSpec[0]);
            // Master Key 核心约束：只能 WRAP，不能 ENCRYPT/DECRYPT
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.WRAP),
                    "Master Key 必须设置 WRAP=true");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.ENCRYPT),
                    "Master Key 不应设置 ENCRYPT=true");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.DECRYPT),
                    "Master Key 不应设置 DECRYPT=true");
            assertEquals(Boolean.FALSE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE),
                    "Master Key 不可导出");
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.TOKEN),
                    "Master Key 必须持久化");
            assertEquals(256, capturedSpec[0].get(KeyAttribute.SIZE));
        }
    }

    @Test
    void createMasterKey_shouldUseLabelFromParameter() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        SecretKey mockKey = mock(SecretKey.class);
        when(mockKeyGen.generateKey()).thenReturn(mockKey);

        KeyAttributesMap[] capturedSpec = new KeyAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyAttributesMap) inv.getArgument(0);
            return null;
        }).when(mockKeyGen).init(any(KeyAttributesMap.class));

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            WrapDemoStep1GenerateMasterKey.createMasterKey("custom-master-key");

            assertEquals("custom-master-key", capturedSpec[0].get(KeyAttribute.LABEL));
        }
    }

    @Test
    void createMasterKey_shouldPropagateExceptionOnProviderFailure() {
        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenThrow(new java.security.NoSuchAlgorithmException("Provider not available"));

            assertThrows(Exception.class,
                    () -> WrapDemoStep1GenerateMasterKey.createMasterKey("fail-label"));
        }
    }
}
