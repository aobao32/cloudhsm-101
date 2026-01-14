package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

public class ExportKeyStep1CreateKey {
    
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
            
            String keyLabel = "TestKeyForPlainTextExport";
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
            
            KeyAttributesMap aesSpec = new KeyAttributesMap();
            aesSpec.put(KeyAttribute.LABEL, keyLabel);
            aesSpec.put(KeyAttribute.SIZE, 256);
            aesSpec.put(KeyAttribute.TOKEN, true);
            aesSpec.put(KeyAttribute.EXTRACTABLE, true);
            aesSpec.put(KeyAttribute.ENCRYPT, true);
            aesSpec.put(KeyAttribute.DECRYPT, true);
            
            keyGen.init(aesSpec);
            SecretKey aesKey = keyGen.generateKey();
            
            System.out.println("AES256密钥创建成功！");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("密钥算法: " + aesKey.getAlgorithm());
            System.out.println("EXTRACTABLE: true");
            
            // 验证密钥可用于AES-256-GCM
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey);
            byte[] testData = "test".getBytes();
            cipher.doFinal(testData);
            System.out.println("AES-256-GCM验证: 成功");
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
