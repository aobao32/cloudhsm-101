package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyReferenceSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;

public class CloudHSMEncryptionByKeyRefID {
    
    public static void main(String[] args) {
        try {
            Security.addProvider(new CloudHsmProvider());

            // 检查认证环境变量
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");

            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.err.println("示例：");
                System.err.println("export HSM_USER=your_cu_username");
                System.err.println("export HSM_PASSWORD=your_cu_password");
                System.exit(1);
            }

            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");

            // 使用密钥引用ID查找密钥
            long keyRefId = 0x00000000000011b6L;

            // 要加密的测试数据
            String plaintext = "Hello CloudHSM! This is a test message.";

            System.out.println("=== CloudHSM 加密信息 ===");
            System.out.println("密钥类型: AES-256");
            System.out.println("密钥引用ID: 0x" + Long.toHexString(keyRefId));
            System.out.println("加密算法: AES-256-GCM");
            System.out.println();

            SecretKey key = findKeyByHandle(keyRefId);

            String encrypted = encryptString(plaintext, key);
            System.out.println("原文: " + plaintext);
            System.out.println("密文 (Base64): " + encrypted);
            System.out.println();
            System.out.println("加密成功！");

        } catch (Exception e) {
            System.err.println("加密失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static SecretKey findKeyByHandle(long keyHandle) throws Exception {
        // 使用KeyStoreWithAttributes通过KeyReferenceSpec查找密钥
        com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes keyStore = 
            com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes.getInstance(
                CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        
        // 创建KeyReferenceSpec
        KeyReferenceSpec keyRefSpec = KeyReferenceSpec.getInstance(keyHandle);
        
        // 通过KeyReferenceSpec查找密钥
        java.security.Key key = keyStore.getKey(keyRefSpec);
        
        if (key == null) {
            throw new Exception("未找到引用ID为 0x" + Long.toHexString(keyHandle) + " 的密钥");
        }

        return (SecretKey) key;
    }
    
    private static String encryptString(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        
        // IV由HSM生成
        byte[] iv = cipher.getIV();
        
        // 输出格式: IV(12字节) + 密文(含认证标签)
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(result);
    }
}
