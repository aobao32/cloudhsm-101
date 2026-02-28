package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;

public class CloudHSMKeyGeneratorAndDownload {

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

            String keyLabel = "MyExtractableAES256Key";
            SecretKey aesKey = createExtractableAES256Key(keyLabel);

            System.out.println("AES256 可提取密钥创建成功！");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("密钥算法: " + aesKey.getAlgorithm());

            // 通过 getEncoded() 获取密钥明文
            byte[] keyBytes = aesKey.getEncoded();
            if (keyBytes != null) {
                System.out.println("密钥明文 (Base64): " + Base64.getEncoder().encodeToString(keyBytes));
                System.out.println("密钥长度: " + (keyBytes.length * 8) + " bits");
            } else {
                System.err.println("警告：getEncoded() 返回 null，请确认已启用 clear key extraction");
                System.err.println("运行: /opt/cloudhsm/bin/configure-jce --enable-clear-key-extraction-in-software");
            }

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 创建 AES256 可提取密钥（EXTRACTABLE=true），允许通过 getEncoded() 导出明文
     */
    public static SecretKey createExtractableAES256Key(String keyLabel) throws Exception {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("keyLabel must not be null or blank");
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);

        KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, 256);
        aesSpec.put(KeyAttribute.EXTRACTABLE, true);   // 允许提取密钥明文
        aesSpec.put(KeyAttribute.TOKEN, true);
        aesSpec.put(KeyAttribute.DERIVE, true);

        keyGen.init(aesSpec);
        return keyGen.generateKey();
    }
}
