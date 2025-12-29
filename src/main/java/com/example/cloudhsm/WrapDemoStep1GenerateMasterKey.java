package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

public class WrapDemoStep1GenerateMasterKey {
    
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
            
            SecretKey masterKey = createMasterKey("new-master-key");
            
            System.out.println("Master Key创建成功！");
            System.out.println("密钥标签: new-master-key");
            System.out.println("密钥算法: " + masterKey.getAlgorithm());
            System.out.println("注意：请管理员通过CLI将此密钥设置为trusted key");
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static SecretKey createMasterKey(String keyLabel) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        
        KeyAttributesMap masterSpec = new KeyAttributesMap();
        masterSpec.put(KeyAttribute.LABEL, keyLabel);
        masterSpec.put(KeyAttribute.SIZE, 256);
        masterSpec.put(KeyAttribute.EXTRACTABLE, false);
        masterSpec.put(KeyAttribute.TOKEN, true);
        masterSpec.put(KeyAttribute.ENCRYPT, false);
        masterSpec.put(KeyAttribute.DECRYPT, false);
        masterSpec.put(KeyAttribute.WRAP, true);
        
        keyGen.init(masterSpec);
        return keyGen.generateKey();
    }
}
