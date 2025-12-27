package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

public class CloudHSMKeyGenerator {
    
    public static void main(String[] args) {
        try {
            // 加载 CloudHSM JCE Provider (SDK 5)
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
            
            // 创建 AES256 持久密钥
            String keyLabel = "MyAES256Key";
            SecretKey aesKey = createPersistentAES256Key(keyLabel);
            
            // 密钥创建成功后输出信息
            System.out.println("AES256 密钥创建成功！");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("密钥算法: " + aesKey.getAlgorithm());
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 创建 AES256 持久密钥并保存在 CloudHSM 中 (SDK 5 方式)
     * 
     * @param keyLabel 密钥标签，用于在 HSM 中标识密钥
     * @return 生成的 AES 密钥
     */
    public static SecretKey createPersistentAES256Key(String keyLabel) throws Exception {
        // SDK 5 方式：使用 KeyAttributesMap 替代 CaviumAESKeyGenParameterSpec
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        
        // 配置密钥属性
        KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.put(KeyAttribute.LABEL, keyLabel);           // 密钥标签
        aesSpec.put(KeyAttribute.SIZE, 256);                 // 密钥长度：256位
        aesSpec.put(KeyAttribute.EXTRACTABLE, false);        // 密钥不可提取（更安全）
        aesSpec.put(KeyAttribute.TOKEN, true);               // 持久化存储在 HSM 中
        
        // 初始化 KeyGenerator
        keyGen.init(aesSpec);
        
        // 生成密钥
        return keyGen.generateKey();
    }
}
