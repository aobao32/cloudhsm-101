package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.Security;
import java.util.Base64;

public class WrapDemoStep2GenerateDataKeyAndWrap {
    
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
            
            // 查找master key
            SecretKey masterKey = findKeyByLabel("new-master-key");
            if (masterKey == null) {
                System.err.println("错误：未找到master key 'new-master-key'，请先运行Step1");
                System.exit(1);
            }
            
            // 生成data key
            SecretKey dataKey = createDataKey("temp-data-key");
            System.out.println("Data Key创建成功！");
            
            // Wrap导出data key
            byte[] wrappedKey = wrapKey(dataKey, masterKey);
            String wrappedKeyBase64 = Base64.getEncoder().encodeToString(wrappedKey);
            
            System.out.println("Data Key已被wrap导出:");
            System.out.println("Wrapped Key (Base64): " + wrappedKeyBase64);
            System.out.println("请将此wrapped key用于Step3");
            
            // 显式销毁 data key（使用标准 Destroyable 接口）
            if (dataKey instanceof Destroyable) {
                ((Destroyable) dataKey).destroy();
                System.out.println("\n✓ Data key 已显式销毁");
            }
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static SecretKey createDataKey(String keyLabel) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        
        KeyAttributesMap dataSpec = new KeyAttributesMap();
        dataSpec.put(KeyAttribute.LABEL, keyLabel);
        dataSpec.put(KeyAttribute.SIZE, 256);
        dataSpec.put(KeyAttribute.TOKEN, false); // session key
        dataSpec.put(KeyAttribute.EXTRACTABLE, true);
        dataSpec.put(KeyAttribute.ENCRYPT, true);
        dataSpec.put(KeyAttribute.DECRYPT, true);
        dataSpec.put(KeyAttribute.WRAP_WITH_TRUSTED, true);
        
        keyGen.init(dataSpec);
        return keyGen.generateKey();
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
    
    public static byte[] wrapKey(SecretKey keyToWrap, SecretKey wrappingKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.WRAP_MODE, wrappingKey);
        return cipher.wrap(keyToWrap);
    }
}
