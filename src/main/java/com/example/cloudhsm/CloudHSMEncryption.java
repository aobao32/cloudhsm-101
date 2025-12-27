package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class CloudHSMEncryption {
    
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

            // 使用密钥标签查找密钥
            String keyLabel = "MyAES256Key";

            // 要加密的测试数据
            String plaintext = "Hello CloudHSM! This is a test message.";

            System.out.println("=== CloudHSM 加密信息 ===");
            System.out.println("密钥类型: AES-256");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("密钥长度: 256位 (32字节)");
            System.out.println();

            SecretKey key = findKeyByLabel(keyLabel);

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

    private static SecretKey findKeyByLabel(String keyLabel) throws Exception {
        // 通过 KeyStore 获取密钥 - CloudHSM SDK 5 推荐方式
        KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);  // CloudHSM KeyStore 不需要密码

        // 使用密钥标签作为别名获取密钥
        SecretKey key = (SecretKey) keyStore.getKey(keyLabel, null);

        if (key == null) {
            throw new Exception("未找到标签为 '" + keyLabel + "' 的密钥");
        }

        return key;
    }
    
    private static String encryptString(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", CloudHsmProvider.PROVIDER_NAME);
        
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(result);
    }
}
