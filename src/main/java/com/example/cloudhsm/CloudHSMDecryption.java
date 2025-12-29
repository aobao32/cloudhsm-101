package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

public class CloudHSMDecryption {

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

            // 预定义的密文
            String ciphertext = "Wejrhl+SZ6FBj1c7lDyVnV9ZCIkJZYvhZPK2d0duWtCl0jvEnqnFzMIOyYXtPfb86oBVBsIwNrwugR7Iv5ypJFFeEg==";

            System.out.println("=== CloudHSM 解密信息 ===");
            System.out.println("密钥类型: AES-256");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("解密算法: AES-256-GCM");
            System.out.println();

            SecretKey key = findKeyByLabel(keyLabel);

            String decrypted = decryptString(ciphertext, key);
            System.out.println("密文 (Base64): " + ciphertext);
            System.out.println("明文: " + decrypted);
            System.out.println();
            System.out.println("解密成功！");

        } catch (Exception e) {
            System.err.println("解密失败: " + e.getMessage());
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

    private static String decryptString(String ciphertext, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(ciphertext);

        // 提取 IV（前12字节，GCM标准）
        byte[] iv = new byte[12];
        System.arraycopy(combined, 0, iv, 0, 12);

        // 提取加密数据（含认证标签）
        byte[] encrypted = new byte[combined.length - 12];
        System.arraycopy(combined, 12, encrypted, 0, encrypted.length);

        // AES-GCM解密
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, "UTF-8");
    }
}
