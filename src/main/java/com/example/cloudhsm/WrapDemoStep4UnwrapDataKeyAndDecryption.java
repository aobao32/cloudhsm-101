package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.util.Base64;

public class WrapDemoStep4UnwrapDataKeyAndDecryption {
    
    // 从Step2获得的wrapped key
    private static final String WRAPPED_KEY_BASE64 = "RrnTldMeA1jTsiiH30ExI7dHs6I/RabQUtG1G4V4Sz7hEpcFyla3RA==";
    // 从Step3获得的GCM加密消息
    private static final String ENCRYPTED_MESSAGE_FROM_STEP3 = "4slO01t2BjL6hFC7DH+Ri3BsZE4YABL2leomx+g9uq70A43FLn6ZK3syglWBadT5oqbxKvZnhgKIw4C1yvKyHJk6/Q==";
    
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
            System.out.println("Wrapped Key密文: " + WRAPPED_KEY_BASE64);
            System.out.println("Step3的加密消息: " + ENCRYPTED_MESSAGE_FROM_STEP3);
            
            // 查找master key
            SecretKey masterKey = findKeyByLabel("new-master-key");
            if (masterKey == null) {
                System.err.println("错误：未找到master key 'new-master-key'");
                System.exit(1);
            }
            
            // Unwrap导入data key
            byte[] wrappedKeyBytes = Base64.getDecoder().decode(WRAPPED_KEY_BASE64);
            SecretKey dataKey = unwrapKey(wrappedKeyBytes, masterKey);
            System.out.println("Data Key已成功unwrap导入到CloudHSM");
            
            // Debug信息：验证dataKey是句柄而非明文
            System.out.println("\n=== Debug: DataKey信息 ===");
            System.out.println("DataKey类型: " + dataKey.getClass().getName());
            System.out.println("DataKey算法: " + dataKey.getAlgorithm());
            System.out.println("DataKey格式: " + dataKey.getFormat());
            byte[] encoded = dataKey.getEncoded();
            if (encoded == null) {
                System.out.println("DataKey.getEncoded()返回值: null (密钥材料未导出)");
            } else {
                System.out.println("DataKey.getEncoded()返回值: 长度=" + encoded.length);
                System.out.println("DataKey.getEncoded() Base64: " + Base64.getEncoder().encodeToString(encoded));
                System.out.println("⚠️  警告：getEncoded()返回了数据，这可能是密钥明文！");
            }
            System.out.println("DataKey对象toString: " + dataKey.toString());
            
            // 尝试检查是否实现了Destroyable接口
            if (dataKey instanceof javax.security.auth.Destroyable) {
                javax.security.auth.Destroyable destroyable = (javax.security.auth.Destroyable) dataKey;
                System.out.println("DataKey是否已销毁: " + destroyable.isDestroyed());
            }
            System.out.println("=========================\n");
            
            // 解密Step3的加密消息
            String decryptedMessage = decryptMessage(ENCRYPTED_MESSAGE_FROM_STEP3, dataKey);
            System.out.println("使用算法: AES/GCM/NoPadding");
            System.out.println("Step3加密消息: " + ENCRYPTED_MESSAGE_FROM_STEP3);
            System.out.println("解密结果: " + decryptedMessage);
            System.out.println("Session结束，data key已从CloudHSM中释放");
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static SecretKey findKeyByLabel(String label) throws Exception {
        try {
            com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes keyStore = 
                com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes.getInstance(
                    CloudHsmProvider.PROVIDER_NAME);
            keyStore.load(null, null);
            
            KeyAttributesMap findSpec = new KeyAttributesMap();
            findSpec.put(KeyAttribute.LABEL, label);
            
            java.security.Key key = keyStore.getKey(findSpec);
            return (SecretKey) key;
        } catch (Exception e) {
            System.err.println("查找密钥失败: " + e.getMessage());
            return null;
        }
    }
    
    public static SecretKey unwrapKey(byte[] wrappedKey, SecretKey unwrappingKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        
        KeyAttributesMap unwrapSpec = new KeyAttributesMap();
        unwrapSpec.put(KeyAttribute.TOKEN, false); // session key
        unwrapSpec.put(KeyAttribute.EXTRACTABLE, false); // 密钥不可导出
        unwrapSpec.put(KeyAttribute.ENCRYPT, true);
        unwrapSpec.put(KeyAttribute.DECRYPT, true);
        unwrapSpec.put(KeyAttribute.LABEL, "temp-data-key");
        
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, unwrapSpec);
        
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
    
    public static String decryptMessage(String encryptedMessage, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedMessage);

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
