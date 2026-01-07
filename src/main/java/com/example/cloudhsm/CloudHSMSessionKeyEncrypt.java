package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfFixedInputData;
import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

public class CloudHSMSessionKeyEncrypt {
    
    private static final String DEVICE_ID = "DEVICE123456";
    private static final String DEVICE_MAC = "AA:BB:CC:DD:EE:FF";
    
    public static void main(String[] args) {
        try {
            Security.addProvider(new CloudHsmProvider());

            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.exit(1);
            }

            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");
            System.out.println();

            // 获取主密钥并在HSM内部派生Session Key
            SecretKey masterKey = findKeyByLabel("MyAES256Key");
            SecretKey sessionKey = deriveSessionKey(masterKey, DEVICE_ID, DEVICE_MAC);
            
            System.out.println("=== Session Key 派生完成 ===");
            System.out.println("设备ID: " + DEVICE_ID);
            System.out.println("设备MAC: " + DEVICE_MAC);
            System.out.println();

            // AES-256-GCM加密
            String plaintext = "Hello CloudHSM! This is a test message.";
            String aad = "additional-auth-data";
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            cipher.updateAAD(aad.getBytes("UTF-8"));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
            byte[] iv = cipher.getIV();
            
            // IV(12字节) + 密文 组合后输出
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            
            System.out.println("=== AES-256-GCM 加密结果 ===");
            System.out.println("密文 (Base64): " + Base64.getEncoder().encodeToString(combined));

        } catch (Exception e) {
            System.err.println("加密失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static SecretKey findKeyByLabel(String keyLabel) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        SecretKey key = (SecretKey) keyStore.getKey(keyLabel, null);
        if (key == null) throw new Exception("未找到标签为 '" + keyLabel + "' 的密钥");
        return key;
    }
    
    private static SecretKey deriveSessionKey(SecretKey masterKey, String deviceId, String deviceMac) throws Exception {
        // 设置派生密钥属性：临时密钥
        KeyAttributesMap keyAttrs = new KeyAttributesMap();
        keyAttrs.put(KeyAttribute.LABEL, "DEVICE_" + deviceId);
        keyAttrs.put(KeyAttribute.SIZE, 256);
        keyAttrs.put(KeyAttribute.TOKEN, false);        // Session Key，不持久化
        keyAttrs.put(KeyAttribute.ENCRYPT, true);
        keyAttrs.put(KeyAttribute.DECRYPT, true);
        
        // 构造派生输入数据
        byte[] label = (deviceId + "|" + deviceMac).getBytes("UTF-8");
        byte[] context = new byte[0];
        AesCmacKdfFixedInputData fixedInputData = new AesCmacKdfFixedInputData(32, label, context);
        
        // 使用AES-CMAC KDF在HSM内部派生密钥
        AesCmacKdfParameterSpec kdfSpec = new AesCmacKdfParameterSpec(keyAttrs, fixedInputData, masterKey);
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        return factory.generateSecret(kdfSpec);
    }
}
