package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfFixedInputData;
import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.Destroyable;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

public class CloudHSMSessionKeyDecrypt {
    
    private static final String DEVICE_ID = "DEVICE123456";
    private static final String DEVICE_MAC = "AA:BB:CC:DD:EE:FF";
    
    // 从加密程序输出中获取的密文（包含IV）
    private static final String CIPHERTEXT_BASE64 = "0oEcvVTi/Tlv8sJM0R6uauul4MCmkApBu5NEojjKjkGSCXhRpWrcHrV5c411dAsGr0ZRUGkYjEURks+TqW2SFddrNA==";
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
            
            // 显式销毁 session key（使用标准 Destroyable 接口）
            if (sessionKey instanceof Destroyable) {
                ((Destroyable) sessionKey).destroy();
                System.out.println("\n✓ Session key 已显式销毁");
            }

        } catch (Exception e) {
            System.err.println("解密失败: " + e.getMessage());
            e.printStackTrace();
        }
        // JVM 退出时，session 自动关闭，所有 session keys 自动删除
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
        keyAttrs.put(KeyAttribute.EXTRACTABLE, false);  // 不可导出
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
