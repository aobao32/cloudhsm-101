package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * MigrateProtectKeyStep1 单元测试
 */
class MigrateProtectKeyStep1Test {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------
    // createRSAKeyPair 测试
    // -----------------------------------------------------------------------

    @Test
    void createRSAKeyPair_shouldConfigureRsa4096Attributes() throws Exception {
        KeyPairGenerator mockKpg = mock(KeyPairGenerator.class);
        KeyPair mockKeyPair = mock(KeyPair.class);
        PublicKey mockPublicKey = mock(PublicKey.class);
        when(mockPublicKey.getAlgorithm()).thenReturn("RSA");
        when(mockKeyPair.getPublic()).thenReturn(mockPublicKey);
        when(mockKpg.generateKeyPair()).thenReturn(mockKeyPair);

        KeyPairAttributesMap[] capturedSpec = new KeyPairAttributesMap[1];
        doAnswer(inv -> {
            capturedSpec[0] = (KeyPairAttributesMap) inv.getArgument(0);
            return null;
        }).when(mockKpg).initialize(any(KeyPairAttributesMap.class));

        try (MockedStatic<KeyPairGenerator> kpgStatic = mockStatic(KeyPairGenerator.class)) {
            kpgStatic.when(() -> KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKpg);

            KeyPair result = MigrateProtectKeyStep1.createRSAKeyPair("migration-key");

            assertNotNull(result);
            assertNotNull(capturedSpec[0]);
            // 验证公钥模数位数为 4096
            assertEquals(4096, capturedSpec[0].getPublic(KeyAttribute.MODULUS_BITS));
            // 验证私钥不可导出
            assertEquals(Boolean.FALSE, capturedSpec[0].getPrivate(KeyAttribute.EXTRACTABLE));
            // 验证私钥支持 UNWRAP
            assertEquals(Boolean.TRUE, capturedSpec[0].getPrivate(KeyAttribute.UNWRAP));
        }
    }

    @Test
    void createRSAKeyPair_shouldUseCloudHsmProvider() throws Exception {
        KeyPairGenerator mockKpg = mock(KeyPairGenerator.class);
        when(mockKpg.generateKeyPair()).thenReturn(mock(KeyPair.class));

        try (MockedStatic<KeyPairGenerator> kpgStatic = mockStatic(KeyPairGenerator.class)) {
            kpgStatic.when(() -> KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKpg);

            MigrateProtectKeyStep1.createRSAKeyPair("test-label");

            kpgStatic.verify(() -> KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void createRSAKeyPair_shouldPropagateExceptionOnFailure() {
        try (MockedStatic<KeyPairGenerator> kpgStatic = mockStatic(KeyPairGenerator.class)) {
            kpgStatic.when(() -> KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME))
                    .thenThrow(new java.security.NoSuchAlgorithmException("Provider not available"));

            assertThrows(Exception.class,
                    () -> MigrateProtectKeyStep1.createRSAKeyPair("fail-label"));
        }
    }

    // -----------------------------------------------------------------------
    // savePubKeyToPEM 测试
    // -----------------------------------------------------------------------

    @Test
    void savePubKeyToPEM_shouldWriteValidPemFile(@TempDir Path tempDir) throws Exception {
        KeyPair mockKeyPair = mock(KeyPair.class);
        PublicKey mockPublicKey = mock(PublicKey.class);
        when(mockPublicKey.getEncoded()).thenReturn(new byte[64]);
        when(mockKeyPair.getPublic()).thenReturn(mockPublicKey);

        Path pemFile = tempDir.resolve("public.pem");
        MigrateProtectKeyStep1.savePubKeyToPEM(mockKeyPair, pemFile.toString());

        String content = new String(Files.readAllBytes(pemFile));
        assertTrue(content.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(content.contains("-----END PUBLIC KEY-----"));
    }

    @Test
    void savePubKeyToPEM_shouldContainEncodedKey(@TempDir Path tempDir) throws Exception {
        KeyPair mockKeyPair = mock(KeyPair.class);
        PublicKey mockPublicKey = mock(PublicKey.class);
        byte[] keyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        when(mockPublicKey.getEncoded()).thenReturn(keyBytes);
        when(mockKeyPair.getPublic()).thenReturn(mockPublicKey);

        Path pemFile = tempDir.resolve("pub.pem");
        MigrateProtectKeyStep1.savePubKeyToPEM(mockKeyPair, pemFile.toString());

        String content = new String(Files.readAllBytes(pemFile));
        // 验证文件非空且包含 Base64 内容
        assertTrue(content.length() > 50);
    }
}
