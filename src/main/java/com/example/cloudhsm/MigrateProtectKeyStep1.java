package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;

import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;

public class MigrateProtectKeyStep1 {

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

            String keyLabel = "migration-key";
            KeyPair keyPair = createRSAKeyPair(keyLabel);

            System.out.println("RSA-4096 密钥对创建成功！");
            System.out.println("密钥标签: " + keyLabel);
            System.out.println("公钥算法: " + keyPair.getPublic().getAlgorithm());

            // 保存公钥到PEM文件
            String pemPath = "../openssl-key/" + keyLabel + "-public.pem";
            savePubKeyToPEM(keyPair, pemPath);
            System.out.println("公钥已保存: " + pemPath);

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static KeyPair createRSAKeyPair(String keyLabel) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);

        KeyPairAttributesMap rsaSpec = new KeyPairAttributesMapBuilder()
                .withPublic(KeyAttribute.LABEL, keyLabel + "-public")
                .withPublic(KeyAttribute.TOKEN, true)
                .withPublic(KeyAttribute.VERIFY, true)
                .withPublic(KeyAttribute.MODULUS_BITS, 4096)
                .withPublic(KeyAttribute.PUBLIC_EXPONENT, new byte[]{0x01, 0x00, 0x01})
                .withPrivate(KeyAttribute.LABEL, keyLabel + "-private")
                .withPrivate(KeyAttribute.TOKEN, true)
                .withPrivate(KeyAttribute.EXTRACTABLE, false)
                .withPrivate(KeyAttribute.SIGN, true)
                .withPrivate(KeyAttribute.UNWRAP, true)
                .build();

        keyPairGen.initialize(rsaSpec);
        return keyPairGen.generateKeyPair();
    }

    public static void savePubKeyToPEM(KeyPair keyPair, String path) throws Exception {
        byte[] encoded = keyPair.getPublic().getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        try (FileWriter fw = new FileWriter(path)) {
            fw.write("-----BEGIN PUBLIC KEY-----\n");
            fw.write(base64);
            fw.write("\n-----END PUBLIC KEY-----\n");
        }
    }
}
