package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;

public class WrapDemoStep3UnwrapDataKeyAndEncryptd {
    
    // 从Step2获得的wrapped key常量 - 请替换为实际值
    private static final String WRAPPED_KEY_BASE64 = "RrnTldMeA1jTsiiH30ExI7dHs6I/RabQUtG1G4V4Sz7hEpcFyla3RA==";
    
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
            
            if (WRAPPED_KEY_BASE64.equals("REPLACE_WITH_ACTUAL_WRAPPED_KEY_FROM_STEP2")) {
                System.err.println("错误：请先将Step2输出的wrapped key替换到代码常量中");
                System.exit(1);
            }
            
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
            
            // 加密测试字符串
            String testMessage = "Hello CloudHSM! This is a test message.";
            String encryptedMessage = encryptMessage(testMessage, dataKey);
            
            System.out.println("使用算法: AES/GCM/NoPadding");
            System.out.println("原始消息: " + testMessage);
            System.out.println("加密结果: " + encryptedMessage);
            System.out.println("Session结束，data key已从CloudHSM中释放");
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static SecretKey findKeyByLabel(String label) throws Exception {
        // 使用KeyStoreWithAttributes查找已存在的密钥 (SDK 5方式)
        try {
            com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes keyStore = 
                com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes.getInstance(
                    CloudHsmProvider.PROVIDER_NAME);
            keyStore.load(null, null);
            
            // 创建查找规格
            KeyAttributesMap findSpec = new KeyAttributesMap();
            findSpec.put(KeyAttribute.LABEL, label);
            
            // 通过属性查找密钥
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
        unwrapSpec.put(KeyAttribute.LABEL, "temp-data-key"); // 添加固定label
        
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, unwrapSpec);
        
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
    
    public static String encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(message.getBytes("UTF-8"));
        
        // IV由HSM生成，加密后获取
        byte[] iv = cipher.getIV();
        
        // 将IV和加密数据组合并编码为Base64
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
}
