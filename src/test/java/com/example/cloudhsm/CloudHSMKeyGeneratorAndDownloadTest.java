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

class CloudHSMKeyGeneratorAndDownloadTest {

    @BeforeEach
    void setUp() {
        Security.removeProvider(CloudHsmProvider.PROVIDER_NAME);
    }

    @Test
    void createExtractableAES256Key_shouldSetExtractableTrue() throws Exception {
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

            SecretKey result = CloudHSMKeyGeneratorAndDownload.createExtractableAES256Key("test-label");

            assertNotNull(result);
            assertEquals("AES", result.getAlgorithm());

            assertNotNull(capturedSpec[0]);
            assertEquals("test-label", capturedSpec[0].get(KeyAttribute.LABEL));
            assertEquals(256, capturedSpec[0].get(KeyAttribute.SIZE));
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.EXTRACTABLE));
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.TOKEN));
            assertEquals(Boolean.TRUE, capturedSpec[0].get(KeyAttribute.DERIVE));
        }
    }

    @Test
    void createExtractableAES256Key_shouldUseCloudHsmProvider() throws Exception {
        KeyGenerator mockKeyGen = mock(KeyGenerator.class);
        when(mockKeyGen.generateKey()).thenReturn(mock(SecretKey.class));

        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenReturn(mockKeyGen);

            CloudHSMKeyGeneratorAndDownload.createExtractableAES256Key("any-label");

            kgStatic.verify(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME));
        }
    }

    @Test
    void createExtractableAES256Key_shouldThrowWhenLabelIsNull() {
        assertThrows(IllegalArgumentException.class,
                () -> CloudHSMKeyGeneratorAndDownload.createExtractableAES256Key(null));
    }

    @Test
    void createExtractableAES256Key_shouldThrowWhenLabelIsBlank() {
        assertThrows(IllegalArgumentException.class,
                () -> CloudHSMKeyGeneratorAndDownload.createExtractableAES256Key("   "));
    }

    @Test
    void createExtractableAES256Key_shouldPropagateException() {
        try (MockedStatic<KeyGenerator> kgStatic = mockStatic(KeyGenerator.class)) {
            kgStatic.when(() -> KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME))
                    .thenThrow(new java.security.NoSuchAlgorithmException("Provider not available"));

            assertThrows(Exception.class,
                    () -> CloudHSMKeyGeneratorAndDownload.createExtractableAES256Key("fail-label"));
        }
    }
}
