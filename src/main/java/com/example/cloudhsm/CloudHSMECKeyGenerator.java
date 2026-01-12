package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class CloudHSMECKeyGenerator {

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

            String keyLabel = "MyECKey";
            KeyPair ecKeyPair = createECKeyPair(keyLabel);

            System.out.println("EC 密钥对创建成功！");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("公钥算法: " + ecKeyPair.getPublic().getAlgorithm());
            System.out.println("私钥算法: " + ecKeyPair.getPrivate().getAlgorithm());

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static KeyPair createECKeyPair(String keyLabel) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);

        KeyPairAttributesMap ecSpec = new KeyPairAttributesMapBuilder()
                .withPublic(KeyAttribute.LABEL, keyLabel + "-public")
                .withPublic(KeyAttribute.TOKEN, true)
                .withPublic(KeyAttribute.EC_PARAMS, EcParams.EC_CURVE_PRIME256)
                .withPublic(KeyAttribute.VERIFY, true)
                .withPrivate(KeyAttribute.LABEL, keyLabel + "-private")
                .withPrivate(KeyAttribute.TOKEN, true)
                .withPrivate(KeyAttribute.EXTRACTABLE, false)
                .withPrivate(KeyAttribute.SIGN, true)
                .build();

        keyPairGen.initialize(ecSpec);
        return keyPairGen.generateKeyPair();
    }
}
