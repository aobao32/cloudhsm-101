## CloudHSM-101 代码说明表格

| 场景 | Java文件名 | 中文解释其使用场景、实现原理 |
|------|-----------|---------------------------|
| 一、使用Java语言JCE Provider SDK调用CloudHSM实现密钥创建、加密、解密 | | |
| 1. 在CloudHSM内创建AES256密钥 | CloudHSMKeyGenerator.java | 使用场景：在CloudHSM加密机内部生成AES-256主密钥，用于后续的加密解密操作。<br>**实现原理**：通过CloudHSM JCE Provider的KeyGenerator生成AES-256密钥，设置TOKEN=true使其持久化存储在HSM内，设置LABEL属性便于后续检索。密钥明文不离开加密机，仅返回密钥句柄。 |
| 2. 使用AES-256-GCM加密 | CloudHSMEncryption.java | 使用场景：使用CloudHSM内的AES-256密钥对明文数据进行加密，适用于需要高安全性的数据保护场景。<br>**实现原理**：通过密钥标签(Label)从CloudHSM检索密钥，使用AES/GCM/NoPadding算法在HSM内部完成加密操作，返回Base64编码的密文。GCM模式提供认证加密，确保数据完整性。 |
| 3. 使用AES-256-GCM加密（按Key Reference ID） | CloudHSMEncryptionByKeyRefID.java | 使用场景：通过密钥的唯一引用ID进行加密，避免Label重名问题，适用于需要精确密钥定位的场景。<br>**实现原理**：使用KeyReferenceSpec通过密钥的唯一ID（如0x11b6）检索密钥，然后执行AES-GCM加密。Key Reference ID是CloudHSM内密钥的唯一标识符，比Label更可靠。 |
| 4. 使用AES-256-GCM解密 | CloudHSMDecryption.java | 使用场景：使用CloudHSM内的AES-256密钥对密文进行解密，恢复原始明文数据。<br>**实现原理**：从Base64密文中提取IV（初始化向量，前12字节）和密文数据，使用GCMParameterSpec配置解密参数，在HSM内部完成解密操作。整个过程密钥明文不离开加密机。 |
| 5. 使用KDF算法生成派生密钥并返回明文 | CloudHSMKeyDerivation.java | 使用场景：IoT场景中为每个设备生成唯一密钥，适用于数十万设备需要独立密钥但不希望在HSM内存储大量密钥的场景。<br>**实现原理**：使用HKDF-SHA384算法，将主密钥、设备ID和MAC地址作为输入，在HSM内派生出32字节设备密钥，并以明文形式返回给应用程序。优点是管理灵活、HSM负载低，缺点是派生密钥暴露给应用程序。 |
| 6. 使用Session Key方式派生并加密 | CloudHSMSessionKeyEncrypt.java | 使用场景：需要为设备派生密钥并在HSM内完成加密的高安全场景，适用于设备数量多但QPS不高（几百级别）的情况。<br>**实现原理**：使用AES-CMAC KDF算法在HSM内派生设备密钥，密钥以Session Key（TOKEN=false）形式临时存储在HSM内，完成AES-GCM加密后返回密文。Session结束后密钥自动释放，不占用永久存储槽位。 |
| 7. 使用Session Key方式派生并解密 | CloudHSMSessionKeyDecrypt.java | 使用场景：对使用Session Key加密的数据进行解密，确保整个加解密过程密钥明文不离开HSM。<br>**实现原理**：使用相同的设备ID和MAC地址重新派生Session Key，从密文中提取IV和密文数据，在HSM内完成AES-GCM解密。Session Key在解密完成后自动释放。 |
| 二、在CloudHSM上使用Key Wrap和Unwrap做密钥导入导出 | | |
| 1. 创建用于Wrap的Master Key | WrapDemoStep1GenerateMasterKey.java | 使用场景：创建专门用于密钥导出封装的主密钥，该密钥需要管理员设置为Trusted Key。<br>**实现原理**：生成AES-256密钥，设置EXTRACTABLE=false（禁止导出自身）、WRAP=true（允许封装其他密钥）、ENCRYPT/DECRYPT=false（不用于数据加解密）。创建后需管理员通过CLI设置trusted=true属性。 |
| 2. 生成Data Key并Wrap导出 | WrapDemoStep2GenerateDataKeyAndWrap.java | 使用场景：生成数据密钥并以加密形式导出，释放HSM存储空间，适用于需要大量密钥但不常用的场景。<br>**实现原理**：生成AES-256 Data Key（设置EXTRACTABLE=true、WRAP_WITH_TRUSTED=true），使用Master Key通过AESWrap/ECB/NoPadding算法（RFC 3394）对Data Key加密导出，返回Base64编码的密文。 |
| 3. Unwrap导入Data Key并加密 | WrapDemoStep3UnwrapDataKeyAndEncryptd.java | 使用场景：将之前导出的密钥密文重新导入HSM并用于数据加密，实现密钥的安全迁移和恢复。<br>**实现原理**：使用Master Key对Wrapped Key密文执行Unwrap操作，在HSM内解密恢复Data Key（作为Session Key），然后使用该密钥执行AES-GCM加密。Session结束后Data Key自动释放。 |
| 4. Unwrap导入Data Key并解密 | WrapDemoStep4UnwrapDataKeyAndDecryption.java | 使用场景：使用Unwrap导入的密钥对之前加密的数据进行解密。<br>**实现原理**：通过Unwrap恢复Data Key，从密文中提取IV和密文数据，在HSM内完成AES-GCM解密。整个过程Data Key明文仅存在于HSM内部，外部只有加密后的Wrapped Key。 |
| 三、使用非对称密钥和Unwrap机制实现私钥迁移到CloudHSM | | |
| 1. 在CloudHSM内生成Migration Key | MigrateProtectKeyStep1.java | 使用场景：为私钥迁移准备非对称密钥对，公钥用于在云外加密，私钥保存在HSM内用于解密。<br>**实现原理**：在HSM内生成RSA-4096密钥对，私钥设置XTRACTABLE=false永久保存在HSM内，公钥导出为PEM格式文件，传输到云外环境用于加密待迁移的私钥。 |
| 2. 在云外对私钥加密 | MigrateProtectKeyStep2.java | 使用场景：在AWS云外受保护环境中，使用Migration Key的公钥对待迁移的私钥进行加密，确保私钥明文不离开受保护区域。<br>**实现原理**：使用OpenSSL将EC私钥转换为PKCS8 DER格式，然后使用RSA-OAEP-SHA512算法和Migration Key公钥加密，生成密文文件。此过程模拟云外操作，不连接CloudHSM。 |
| 3. Unwrap导入私钥到CloudHSM | MigrateProtectKeyStep3.java | 使用场景：将加密后的私钥密文安全导入到CloudHSM，实现跨环境的私钥迁移。<br>**实现原理**：读取加密的私钥密文，使用Migration Key的私钥通过Unwrap操作在HSM内解密，恢复原始EC私钥并设置为永久密钥（TOKEN=true、EXTRACTABLE=false），确保私钥明文仅存在于HSM内。 |
| 四、不推荐有风险操作例子 | | |
| 1. 导入EC私钥明文到CloudHSM | ImportPrivateKeyInPlainText.java | 使用场景：将外部生成的EC私钥明文直接导入CloudHSM（不推荐，仅供调试参考）。<br>**实现原理**：读取PEM格式的EC私钥文件，提取SEC1格式的私钥字节，使用KeyFactory和KeyAttributesMap将私钥导入HSM并设置为永久密钥。此方法存在私钥明文暴露风险，生产环境应使用Unwrap机制。 |
| 2. 导入AES256密钥明文到CloudHSM | ImportAES256KeyInPlainText.java | 使用场景：将外部的AES-256密钥明文直接导入CloudHSM（不推荐，仅供调试参考）。<br>**实现原理**：将Base64编码的AES密钥解码为字节数组，使用SecretKeyFactory和KeyAttributesMap导入HSM并设置为永久密钥。此方法存在密钥明文暴露风险，生产环境应使用Wrap/Unwrap机制。 |
| 3. 创建可导出的密钥 | ExportKeyStep1CreateKey.java | 使用场景：创建一个允许明文导出的AES-256密钥（不推荐，仅供测试）。<br>**实现原理**：生成AES-256密钥并设置EXTRACTABLE=true属性，允许后续通过getEncoded()方法导出密钥明文。此操作违背HSM"密钥不出加密机"的安全原则。 |
| 4. 导出密钥明文 | ExportKeyStep2ExportInPlainText.java | 使用场景：将HSM内的密钥以明文形式导出（不推荐，存在严重安全风险）。<br>**实现原理**：通过Key Reference ID检索密钥，调用getEncoded()方法获取密钥明文字节，保存为PEM文件。需要预先配置JCE SDK允许明文导出（--enable-clear-key-extraction-in-software）。此操作破坏HSM安全性。 |
| 5. 创建可提取密钥并下载 | CloudHSMKeyGeneratorAndDownload.java | 使用场景：创建AES-256密钥并立即导出明文（不推荐，仅供演示getEncoded()用法）。<br>**实现原理**：生成EXTRACTABLE=true的AES-256密钥，立即调用getEncoded()获取密钥明文并以Base64格式输出。此方法将密钥明文暴露给应用程序，违背HSM安全设计原则。 |

说明：

- 第一、二、三章节的代码是推荐的安全实践，遵循"密钥明文不离开加密机"的原则
- 第四章节的代码标注为"不推荐"，仅作为技术参考，生产环境应避免使用
- 所有代码都需要通过环境变量HSM_USER和HSM_PASSWORD提供CloudHSM的认证信息
