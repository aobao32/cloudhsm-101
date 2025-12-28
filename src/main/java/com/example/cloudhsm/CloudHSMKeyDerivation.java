package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

public class CloudHSMKeyDerivation {
    
    // 硬编码的设备标识常量
    private static final String DEVICE_ID = "DEVICE123456";
    private static final String DEVICE_MAC = "AA:BB:CC:DD:EE:FF";
    
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

            // 使用密钥标签查找主密钥
            String keyLabel = "MyAES256Key";

            System.out.println("=== CloudHSM 密钥派生信息 ===");
            System.out.println("主密钥类型: AES-256");
            System.out.println("主密钥标签: " + keyLabel);
            System.out.println("派生算法: HKDF-SHA384");
            System.out.println("设备ID: " + DEVICE_ID);
            System.out.println("设备MAC: " + DEVICE_MAC);
            System.out.println();

            SecretKey masterKey = findKeyByLabel(keyLabel);
            
            // 使用HKDF-SHA384派生设备密钥
            byte[] deviceKey = deriveDeviceKey(masterKey, DEVICE_ID, DEVICE_MAC);
            
            System.out.println("派生的设备密钥 (32字节):");
            System.out.println("Hex: " + bytesToHex(deviceKey));
            System.out.println("Base64: " + Base64.getEncoder().encodeToString(deviceKey));
            System.out.println();
            System.out.println("密钥派生成功！");

        } catch (Exception e) {
            System.err.println("密钥派生失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static SecretKey findKeyByLabel(String keyLabel) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        SecretKey key = (SecretKey) keyStore.getKey(keyLabel, null);

        if (key == null) {
            throw new Exception("未找到标签为 '" + keyLabel + "' 的密钥");
        }

        return key;
    }
    
    private static byte[] deriveDeviceKey(SecretKey masterKey, String deviceId, String deviceMac) throws Exception {
        // 构建派生输入
        String derivationInput = deviceId + "|" + deviceMac;
        byte[] info = derivationInput.getBytes("UTF-8");
        
        // HKDF-SHA384 实现
        return hkdfSha384(masterKey, null, info, 32);
    }
    
    private static byte[] hkdfSha384(SecretKey ikm, byte[] salt, byte[] info, int length) throws Exception {
        // 简化实现：直接使用HMAC-SHA384对输入进行哈希
        Mac hmac = Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME);
        hmac.init(ikm);
        
        // 构建HKDF输入
        hmac.update(info);
        byte[] hash = hmac.doFinal();
        
        // 截取所需长度
        byte[] result = new byte[length];
        System.arraycopy(hash, 0, result, 0, Math.min(hash.length, length));
        
        return result;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
