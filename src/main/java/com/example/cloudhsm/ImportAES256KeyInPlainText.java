package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.Security;
import java.util.Base64;

public class ImportAES256KeyInPlainText {
    
    public static void main(String[] args) {
        try {
            Security.addProvider(new CloudHsmProvider());
            
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.exit(1);
            }
            
            System.out.println("=== CloudHSM AES256密钥导入演示 ===");
            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");
            
            String base64Key = "7Q1vz690lk6ghuD3+uo8C+pKmij7KBNkYKsX6mVGgSk=";
            String keyLabel = "importedAES256Key";
            
            SecretKey importedKey = importAES256Key(base64Key, keyLabel);
            validateImportedKey(importedKey);
            
            System.out.println("\n✅ AES256密钥导入成功完成！");
            System.out.println("密钥已作为永久密钥存储在CloudHSM中，标签为: " + keyLabel);
            
        } catch (Exception e) {
            System.err.println("❌ 操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static SecretKey importAES256Key(String base64Key, String keyLabel) throws Exception {
        System.out.println("\n--- 开始导入AES256密钥 ---");
        
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        System.out.println("1. 解码Base64密钥，长度: " + keyBytes.length + " 字节");
        
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("AES256密钥必须是32字节，当前: " + keyBytes.length);
        }
        
        System.out.println("2. 创建KeyAttributesMap并设置属性...");
        KeyAttributesMap attributes = new KeyAttributesMap();
        attributes.put(KeyAttribute.KEY_TYPE, KeyType.AES);
        attributes.put(KeyAttribute.VALUE, keyBytes);
        attributes.put(KeyAttribute.LABEL, keyLabel);
        attributes.put(KeyAttribute.TOKEN, true);
        attributes.put(KeyAttribute.EXTRACTABLE, false);
        attributes.put(KeyAttribute.ENCRYPT, true);
        attributes.put(KeyAttribute.DECRYPT, true);
        
        System.out.println("3. 使用SecretKeyFactory导入密钥到CloudHSM...");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        SecretKey secretKey = keyFactory.generateSecret(attributes);
        
        System.out.println("✅ AES256密钥导入成功！");
        return secretKey;
    }
    
    public static void validateImportedKey(SecretKey secretKey) throws Exception {
        System.out.println("\n--- 验证导入的密钥 ---");
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        String testMessage = "Hello CloudHSM! Test message for AES256 key validation.";
        byte[] encrypted = cipher.doFinal(testMessage.getBytes("UTF-8"));
        
        System.out.println("✅ 密钥验证成功！");
        System.out.println("   加密数据长度: " + encrypted.length + " 字节");
        System.out.println("   密钥已永久存储在CloudHSM中");
    }
}
