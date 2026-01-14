package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;

public class MigrateProtectKeyStep3 {

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

            String encryptedKeyPath = "../openssl-key/ec_private_key.pem-encrypted";

            if (!Files.exists(Paths.get(encryptedKeyPath))) {
                System.err.println("错误：未找到加密文件: " + encryptedKeyPath);
                System.exit(1);
            }

            // 读取加密的密钥数据
            byte[] wrappedKey = Files.readAllBytes(Paths.get(encryptedKeyPath));
            System.out.println("加密文件大小: " + wrappedKey.length + " 字节");

            // 查找 migration key
            PrivateKey migrationKey = findPrivateKeyByLabel("migration-key-private");
            if (migrationKey == null) {
                System.err.println("错误：未找到 migration-key-private");
                System.exit(1);
            }

            System.out.println("找到 migration-key-private");

            // Unwrap 导入 EC 私钥到 CloudHSM
            PrivateKey importedKey = unwrapECPrivateKey(wrappedKey, migrationKey);

            System.out.println("EC 私钥已成功 unwrap 导入到 CloudHSM");
            System.out.println("密钥标签: imported-ec-key");
            System.out.println("密钥算法: " + importedKey.getAlgorithm());

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static PrivateKey findPrivateKeyByLabel(String label) throws Exception {
        KeyStoreWithAttributes keyStore = KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyAttributesMap findSpec = new KeyAttributesMap();
        findSpec.put(KeyAttribute.LABEL, label);

        return (PrivateKey) keyStore.getKey(findSpec);
    }

    public static PrivateKey unwrapECPrivateKey(byte[] wrappedKey, PrivateKey unwrappingKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", CloudHsmProvider.PROVIDER_NAME);

        KeyAttributesMap unwrapSpec = new KeyAttributesMap();
        unwrapSpec.put(KeyAttribute.TOKEN, true);
        unwrapSpec.put(KeyAttribute.SIGN, true);
        unwrapSpec.put(KeyAttribute.EXTRACTABLE, false);
        unwrapSpec.put(KeyAttribute.LABEL, "imported-ec-key");

        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, unwrapSpec);

        return (PrivateKey) cipher.unwrap(wrappedKey, "EC", Cipher.PRIVATE_KEY);
    }
}
