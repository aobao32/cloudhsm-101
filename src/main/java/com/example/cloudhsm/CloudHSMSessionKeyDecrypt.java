package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

public class CloudHSMSessionKeyDecrypt {
    
    private static final String DEVICE_ID = "DEVICE123456";
    private static final String DEVICE_MAC = "AA:BB:CC:DD:EE:FF";
    
    // 从加密程序输出中获取的密文（包含IV）
    private static final String CIPHERTEXT_BASE64 = "m7OVZRJ2fh3exj/E7X12aX7NNSgz81cko9Nxnr9qL7h/Y9iTagWS2iVyR0ojgBXgmEh+Yj0CpHAepAUebQq0hMDZvw==";
    private static final String AAD = "additional-auth-data";
    
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

            // 获取主密钥并派生Session Key
            SecretKey masterKey = findKeyByLabel("MyAES256Key");
            SecretKey sessionKey = deriveSessionKey(masterKey, DEVICE_ID, DEVICE_MAC);
            
            System.out.println("=== Session Key 派生完成 ===");
            System.out.println("设备ID: " + DEVICE_ID);
            System.out.println("设备MAC: " + DEVICE_MAC);
            System.out.println();

            // 解析密文：前12字节是IV，其余是密文
            byte[] combined = Base64.getDecoder().decode(CIPHERTEXT_BASE64);
            byte[] iv = new byte[12];
            byte[] ciphertext = new byte[combined.length - 12];
            System.arraycopy(combined, 0, iv, 0, 12);
            System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);
            
            // AES-256-GCM解密
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmSpec);
            cipher.updateAAD(AAD.getBytes("UTF-8"));
            byte[] plaintext = cipher.doFinal(ciphertext);
            
            System.out.println("=== AES-256-GCM 解密结果 ===");
            System.out.println("明文: " + new String(plaintext, "UTF-8"));

        } catch (Exception e) {
            System.err.println("解密失败: " + e.getMessage());
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
        Mac hmac = Mac.getInstance("HmacSHA384", CloudHsmProvider.PROVIDER_NAME);
        hmac.init(masterKey);
        byte[] derivedBytes = hmac.doFinal((deviceId + "|" + deviceMac).getBytes("UTF-8"));
        
        byte[] keyBytes = new byte[32];
        System.arraycopy(derivedBytes, 0, keyBytes, 0, 32);
        
        KeyAttributesMap keyAttrs = new KeyAttributesMap();
        keyAttrs.put(KeyAttribute.LABEL, "DerivedSessionKey");
        keyAttrs.put(KeyAttribute.TOKEN, false);
        keyAttrs.put(KeyAttribute.EXTRACTABLE, false);
        keyAttrs.put(KeyAttribute.ENCRYPT, true);
        keyAttrs.put(KeyAttribute.DECRYPT, true);
        keyAttrs.put(KeyAttribute.VALUE, keyBytes);
        
        return SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME).generateSecret(keyAttrs);
    }
}
