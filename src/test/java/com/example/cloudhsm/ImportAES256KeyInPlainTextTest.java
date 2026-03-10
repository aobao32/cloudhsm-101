package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class ImportAES256KeyInPlainTextTest {
    
    @BeforeAll
    static void setup() throws Exception {
        Security.addProvider(new CloudHsmProvider());
    }
    
    @Test
    void testBase64Decode() {
        String base64Key = "7Q1vz690lk6ghuD3+uo8C+pKmij7KBNkYKsX6mVGgSk=";
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        assertEquals(32, keyBytes.length, "AES256密钥应为32字节");
    }
    
    @Test
    void testInvalidKeyLength() throws Exception {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            ImportAES256KeyInPlainText.importAES256Key(shortKey, "testKey");
        });
        
        assertTrue(exception.getMessage().contains("AES256密钥必须是32字节"));
    }
    
    @Test
    void testKeyAttributesMap() throws Exception {
        byte[] keyBytes = new byte[32];
        String keyLabel = "testAES256Key";
        
        KeyAttributesMap attributes = new KeyAttributesMap();
        attributes.put(KeyAttribute.KEY_TYPE, KeyType.AES);
        attributes.put(KeyAttribute.VALUE, keyBytes);
        attributes.put(KeyAttribute.LABEL, keyLabel);
        attributes.put(KeyAttribute.TOKEN, true);
        attributes.put(KeyAttribute.EXTRACTABLE, false);
        attributes.put(KeyAttribute.ENCRYPT, true);
        attributes.put(KeyAttribute.DECRYPT, true);
        
        assertEquals(KeyType.AES, attributes.get(KeyAttribute.KEY_TYPE));
        assertEquals(keyLabel, attributes.get(KeyAttribute.LABEL));
        assertTrue((Boolean) attributes.get(KeyAttribute.TOKEN));
        assertFalse((Boolean) attributes.get(KeyAttribute.EXTRACTABLE));
    }
}
