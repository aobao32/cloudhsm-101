# CloudHSM Java SDK（JCE Provider）使用入门

CloudHSM是AWS的云上硬件安全模块服务，由于加密相关专业性比较复杂，导致学习入门、测试门槛较高。本文介绍如何Java语言（JCE Provider SDK）访问CloudHSM完成密钥生成、加密、解密任务，同时还会提供密钥导出Wrap/Unwrap的样例代码。

<details>
<summary>点击这里阅读全部</summary>

## 一、使用Java语言JCE Provider SDK调用CloudHSM实现密钥创建、加密、解密的例子

### 1、开发环境准备及JCE Provider SDK安装

本文以在AWS云端使用EC2虚拟机的Ubuntu 22.04操作系统为例进行开发，且开发环境和运行环境都在云上，这样网络默认可连通，避免调试过程中的网络访问造成调试困难。

下载Amazon版本的OpenJDK，Amazon Corretto 17。

```shell
wget -O - https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/corretto-keyring.gpg] https://apt.corretto.aws stable main" | sudo tee /etc/apt/sources.list.d/corretto.list
sudo apt-get update; sudo apt-get install -y maven java-17-amazon-corretto-jdk 
```

JDK安装完毕。CloudHSM的SDK有版本3和版本5两个系列，版本3在2025年退役，本文使用最新的版本5系列。

以Ubuntu 22.04系统x86_64架构处理器为例，从官网下载最新版本的CloudHSM的JCE Provider SDK：

```shell
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Jammy/cloudhsm-jce_latest_u22.04_amd64.deb
sudo apt install ./cloudhsm-jce_latest_u22.04_amd64.deb
```

替换如下命令中的CloudHSM IP为集群内的节点IP完成配置：

```shell
sudo /opt/cloudhsm/bin/configure-jce -a 172.31.24.131
```

确认如下三个文件正常：（其中JCE版本号可能有所不同）

```shell
ls -l /opt/cloudhsm/java/cloudhsm-jce-5.16.2.jar
ls -l /opt/cloudhsm/bin/configure-jce
ls -l /opt/cloudhsm/bin/jce_info
```

仔细检查以上文件名和路径，确保返回结果正确。由此CloudHSM SDK开发环境准备完毕。下面开始准备Java代码和编译。

### 2、获取Java样例代码并编译构建Jar包

Java代码和pom.xml文件可参考Github上的[示例](https://github.com/aobao32/cloudhsm-101)。执行如下命令下载代码：

```shell
git clone git@github.com:aobao32/cloudhsm-101.git
cd cloudhsm-101/
```

在编译环节，为了运行环境无须安装CloudHSM JCE Provider SDK，因此会编译fat-jar，将所有库打包到一个jar包。因此需要将cloudhsm的jce的jar包集成到mvn本地库。

```shell
mvn install:install-file \
  -Dfile=/opt/cloudhsm/java/cloudhsm-jce-5.16.2.jar \
  -DgroupId=com.amazonaws \
  -DartifactId=cloudhsm-jce \
  -Dversion=5.16.2 \
  -Dpackaging=jar
```

执行编译。注意本例中的密钥ID、要加密的明文、要解密的密文是hardcode方式写在样例代码中的，如果改动的话要重新编译代码。

```shell
mvn clean package
```

在本例的pom.xml中，使用了shade打包方式，因此打包后的jar包体积会达到12MB，即包含了JCE Provider的Jar。打包时候会把如下几个不同类型、不同功能的测试每个方法都独立打一个jar包，方便学习和参考。执行`ls -lh target/*.jar`命令可看到如下返回结果。

```shell
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-decryption-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 30K Dec 29 06:12 target/cloudhsm-demo-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-encryption-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-keyderivation-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-keygen-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-sessionkey-decrypt-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/cloudhsm-sessionkey-encrypt-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/wrap-demo-step-1-generate-master-key-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/wrap-demo-step-2-generate-data-key-and-wrap-1.0-SNAPSHOT.jar
-rw-r--r-- 1 ubuntu ubuntu 12M Dec 29 06:12 target/wrap-demo-step-3-unwrap-data-key-and-encryptd-1.0-SNAPSHOT.jar
```

以上就构建好了创建密钥、加密、解密等几个包。如果您对AWS VPC网络不了解，那么在开发者本机调试可能遇到网络连通性问题。因此建议在开始学习时候以上编译代码的开发环境和运行环境都在AWS云上的EC2虚拟机内，这样避免网络调试的困难。下面转向运行环境。

### 3、在CloudHSM内创建一个AES256算法的密钥作为Master key主密钥

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/CloudHSMKeyGenerator.java。

如果您此时CloudHSM集群是单节点的测试集群，还要额外使用`--disable-key-availability-check`参数。否则后续会报告`Cannot perform the requested key operation as the key must be available on at least 2 HSMs`。设置单节点运行禁用可用性检查：

```shell
sudo /opt/cloudhsm/bin/configure-jce --disable-key-availability-check
```

运行前，通过环境变量加载CloudHSM的用户user01的用户名和密码：

```shell
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
```

运行Java代码：

```shell
java -jar target/cloudhsm-keygen-1.0-SNAPSHOT.jar
```

运行后返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
AES256 密钥创建成功！
密钥标签: MyAES256Key
密钥算法: AES
```

可看到密钥创建成功。

为了验证密钥创建成功，可通过CloudHSM CLI登录，查看刚创建的密钥是否存在。

现在使用cloudhsm-cli登录去确认密钥创建成功。如果您的集群是单节点，还要额外增加一条`--disable-key-availability-check`参数。否则后续查询时候会报告`Cannot perform the requested key operation as the key must be available on at least 2 HSMs`。接下来执行如下命令登录：

```shell
sudo /opt/cloudhsm/bin/configure-cli --disable-key-availability-check
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username user01 --role crypto-user
key list --verbose
```

由此即可显示详细密钥属性：

```shell
aws-cloudhsm > key list --verbose
{
  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x0000000000002a77",
        "key-info": {
          "key-owners": [
            {
              "username": "user01",
              "key-coverage": "full"
            }
          ],
          "shared-users": [],
          "key-quorum-values": {
            "manage-key-quorum-value": 0,
            "use-key-quorum-value": 0
          },
          "cluster-coverage": "full"
        },
        "attributes": {
          "key-type": "aes",
          "label": "MyAES256Key",
          "id": "0x",
          "check-value": "0x63f13c",
          "class": "secret-key",
          "encrypt": true,
          "decrypt": true,
          "token": true,
          "always-sensitive": true,
          "derive": false,
          "destroyable": true,
          "extractable": false,
          "local": true,
          "modifiable": true,
          "never-extractable": true,
          "private": true,
          "sensitive": true,
          "sign": true,
          "trusted": false,
          "unwrap": true,
          "verify": true,
          "wrap": true,
          "wrap-with-trusted": false,
          "key-length-bytes": 32
        }
      }
    ],
    "total_key_count": 1,
    "returned_key_count": 1
  }
}
```

如果要删除某个key，可以使用如下命令：

```shell
key delete --filter key-reference=0x0000000000000e74
```

即可删除密钥。

### 4、使用AES-256-GCM算法用主密钥对文本执行加密、解密

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/CloudHSMEncryption.java和CloudHSMDecryption.java。

上文已经在CloudHSM内创建了密钥，现在对一串文本进行加密。加密时候的方法是在CloudHSM加密机内部执行，密钥明文不离开加密机。

如果修改了代码中的密钥标识符，那么要重新构建包。如果之前已经通过环境变量设置了密钥，那么这一步可以不用设置。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/cloudhsm-encryption-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
=== CloudHSM 加密信息 ===
密钥类型: AES-256
密钥标签: MyAES256Key
加密算法: AES-256-GCM

原文: Hello CloudHSM! This is a test message.
密文 (Base64): HRGNyxEjx5IUq6Ztr4+b/U4y0BeB/tcBBgWOe00wlgYpg7W+87pGw/sYsyVD4AqXhDsueQWpnk38jRITUildD2q2JA==

加密成功！
```

接下来进行解密测试，将以上密文代入到解密的代码中，再执行命令如下。如果之前已经通过环境变量设置了密钥，那么这一步可以不用设置。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/cloudhsm-decryption-1.0-SNAPSHOT.jar
```

执行结果如下：

```shell
使用用户 user01 连接到CloudHSM...
=== CloudHSM 解密信息 ===
密钥类型: AES-256
密钥标签: MyAES256Key
解密算法: AES-256-GCM

密文 (Base64): HRGNyxEjx5IUq6Ztr4+b/U4y0BeB/tcBBgWOe00wlgYpg7W+87pGw/sYsyVD4AqXhDsueQWpnk38jRITUildD2q2JA==
明文: Hello CloudHSM! This is a test message.

解密成功！
```

备注：以上代码示例中，使用的是密钥的Label标签属性。但Label是不唯一的，可以生成重名密钥。在CloudHSM内，密钥的唯一标识是Key Reference ID，因此可使用这个唯一ID来避免重名问题。本文开头Github的：src/main/java/com/example/cloudhsm/CloudHSMEncryptionByKeyRefID.java 这段代码就是以Key Reference ID为例进行的调用。

### 5、使用KDF算法生成派生密钥并明文返回给客户端

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/CloudHSMKeyDerivation.java。

在IoT场景中，所有设备使用唯一的主密钥进行加密可能不够安全，每个设备都分配一个独立的密钥这样管理成本又很高，且在数十万设备时候会超出CloudHSM集群存储的密钥数量上限。此时的办法可将设备的唯一标识、网卡MAC地址作为参数，使用密钥派生算法（KDF）生成新的派生密钥作为本设备的唯一密钥。

主要过程是：

- （1）应用程序将设备唯一标识符（设备ID和MAC地址）传入CloudHSM；
- （2）CloudHSM内部使用主密钥Master Key和设备标识符，通过HKDF-SHA384算法进行密钥派生；
- （3）派生出的设备密钥以明文形式返回给应用程序；
- （4）应用程序获得32字节的设备专用密钥，可用于后续的加解密操作。

流程如下：

```shell
  ┌─────────────┐
  │ 主密钥(HSM) │  AES-256 (MyAES256Key)
  └──────┬──────┘
         │ HKDF-SHA384
         │ (设备ID + MAC)
         ▼
  ┌─────────────┐
  │ 派生密钥    │  32字节明文密钥
  │ (返回应用)  │  返回给应用程序
  └─────────────┘
```

本文的例子使用HKDF-SHA384算法，由此可保证每个设备都有独一无二的密钥，且本密钥可随时由主密钥和设备唯一信息推导生成。在本例中，我们直接将派生密钥（即针对每个IoT设备的设备密钥）以明文方式返回给应用程序进行后续处理。

这种方式的优点是管理灵活，CloudHSM只需要进行密钥派生操作，无需承担大量的加解密计算负载，适合数十万IoT设备的高并发场景。但缺点是派生密钥会暴露给应用程序，安全性相对较低。

在确保前文整体maven构建成功的情况下，在target目录内已经有现成的jar包，可直接运行。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/cloudhsm-keyderivation-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户: user01 连接到CloudHSM...
=== CloudHSM 密钥派生信息 ===
主密钥类型: AES-256
主密钥标签: MyAES256Key
派生算法: HKDF-SHA384
设备ID: DEVICE123456
设备MAC: AA:BB:CC:DD:EE:FF

派生的设备密钥 (32字节):
Hex: 83a813f5a70f3867ab27c5e3d8715026730af7b42ed23e7baa6d7e2e0bc45f9e
Base64: g6gT9acPOGerJ8Xj2HFQJnMK97Qu0j57qm1+LgvEX54=

密钥派生成功！
```

由此看到派生密钥成功生成并以明文形式返回给应用程序。应用程序可以使用这个32字节的设备专用密钥进行后续的加解密操作。

### 6、在CloudHSM内以Session Key方式进行密钥派生并加密、解密

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/CloudHSMSessionKeyEncrypt.java和CloudHSMSessionKeyDecrypt.java。

上一个例子，派生密钥直接用明文方式返回应用客户端，这样的好处是管理灵活，同时几十万IoT设备需要大量数据时候，CloudHSM加密机只需要生成派生密钥，而无需直接承担加解密过程的开销，避免了CloudHSM加密机的密钥数、并发连接被打爆。但由此加解密安全性不足，未能完全让密钥在CloudHSM内部完成加密。因此如果设备较多，但是每秒QPS并发在相对不高（例如几百QPS）的情况下，一种更加安全的做法是全程在CloudHSM完成加密解密。

主要过程是：

- （1）用主密钥Master Key对设备唯一标识符（如设备ID和MAC地址）进行AES-CMAC KDF派生算法，在CloudHSM内部计算获得派生后的设备密钥；
- （2）设备密钥以Session Key临时密钥的方式保存在CloudHSM中，此时会占用CloudHSM的密钥存储槽位一个，但是占用时长仅限本Session；
- （3）应用端传入要加密的数据，在CloudHSM内部使用设备密钥完成加密，密文返回给应用端；
- （4）释放Session，此时CloudHSM内的Session Key将释放不会占用存储槽位，而永久保存的密钥依然只有主密钥Master Key一个。

流程如下：

```shell
  ┌─────────────┐
  │ 主密钥(HSM) │  AES-256 (MyAES256Key)
  └──────┬──────┘
         │ AES-CMAC KDF
         │ (设备ID + MAC)
         ▼
  ┌─────────────┐
  │设备密钥(HSM) │  AES-256 (DEVICE_xxx)
  │ TOKEN=false │  Session Key，不持久化
  └──────┬──────┘
         │ AES-GCM加密
         ▼
  ┌─────────────┐
  │ 业务数据密文│  IV(12) + [加密数据 + 认证标签(16)]
  └─────────────┘
```

以上方式可以针对较大设备数量、但是每秒并发在几百QPS的情况下有效满足派生加密的需求，且加密和解密全程在CloudHSM内，即实现了最终目标密钥明文不出加密机。

由于前边Maven已经构建好了Jar包，这里直接运行就可以了：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/cloudhsm-sessionkey-encrypt-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户: user01 连接到CloudHSM...

=== Session Key 派生完成 ===
设备ID: DEVICE123456
设备MAC: AA:BB:CC:DD:EE:FF

=== AES-256-GCM 加密结果 ===
密文 (Base64): 0oEcvVTi/Tlv8sJM0R6uauul4MCmkApBu5NEojjKjkGSCXhRpWrcHrV5c411dAsGr0ZRUGkYjEURks+TqW2SFddrNA==
```

由此看到派生后的Session Key在CloudHSM内加密成功。

接下来测试解密，将这个密文更新到`CloudHSMSessionKeyDecrypt.java`代码中的密文，然后重新构建，并执行：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -cp target/cloudhsm-sessionkey-encrypt-1.0-SNAPSHOT.jar com.example.cloudhsm.CloudHSMSessionKeyDecrypt
```

解密后返回提示信息：

```shell
使用用户: user01 连接到CloudHSM...

=== Session Key 派生完成 ===
设备ID: DEVICE123456
设备MAC: AA:BB:CC:DD:EE:FF

=== AES-256-GCM 解密结果 ===
明文: Hello CloudHSM! This is a test message.
```

由此派生算法的例子完成。

## 二、在CloudHSM上使用Key Wrap和Unwrap做密钥导入导出

### 1、密钥导出机制

在前一个章节的Java SDK示例代码中，展示了一个生成派生密钥并将派生后的明文作为设备密钥返回给应用程序的例子。这个例子并不是密钥的明文导出，因为负责派生的主密钥是AES256，这个主密钥并未以明文形式或者密文形式被导出，而是借助主密钥、输入的设备序号、设备网卡MAC地址派生计算了一个新密钥。真正进行一个现有密钥的完整导出的唯一方法是使用Key Wrap/Unwrap功能。

除了在CloudHSM内部直接完成加密、解密的操作外，CloudHSM支持将密钥以加密形式导出，被称为Key Wrap。CloudHSM不支持直接将密钥的明文导出。CloudHSM的Key Wrap是以加密形式，经由某一个受信任（Trusted Key）主密钥来完成，将被导出的Key进行加密并把密文从CloudHSM输出到外部。做完Key Wrap后，CloudHSM内可选不保存此密钥，以释放CloudHSM密钥存储的槽位，避免过多密钥完全占用CloudHSM的存储能力。导出的密钥可在任何时间做unwrap导入，导入CloudHSM过程将由受信任（Trusted Key）主密钥来完成解密，在CloudHSM内重新让导入的密钥可用。

在主密钥是AES256类型的情况下，对一个密钥做Wrap导出，使用的算法是AESWrap/ECB/NoPadding (RFC 3394) 。这是符合NIST SP 800-38F标准的安全的算法，提供256位强度的安全。此外，为了控制那些密钥可以被导出，在创建密钥时候需要设置对应属性，主要包括如下：

Master Key主密钥属性：

- extractable=false，禁止导出密钥（本密钥自身是主密钥，禁止导出）
- trusted=true，本参数必须由CloudHSM admin额外手工设置，普通用户创建密钥时候无法添加此属性

被导出的密钥需要设置属性：

- extractable=true，允许导出
- wrap-with-trusted=true，仅允许受信任的密钥(trusted=true)对当前密钥加密后导出

下面是Java SDK的例子的介绍。在上文部署开发环境时候，有关代码已经一并被下载并打包了，因此这里直接运行即可。

### 2、创建用于Wrap Key的Master Key主密钥

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/WrapDemoStep1GenerateMasterKey.java。

首先创建主密钥。在本文的样例代码中，已经为主密钥设置了对应的属性，主密钥本身不可导出，不可用于加密和解密，只能用于做Wrap导出时候的封装使用。

运行刚才已经构建好的Jar包，记得提前通过环境变量设置访问CloudHSM的用户名和密码。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/wrap-demo-step-1-generate-master-key-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
Master Key创建成功！
密钥标签: new-master-key
密钥算法: AES
注意：请管理员通过CLI将此密钥设置为trusted key
```

由此创建了一个标签为`new-master-key`的主密钥。接下来为其设置Trust信任密钥这个特殊属性。

### 3、通过CloudHSM CLI检索Master Key并设置属性为Trusted Key

先以普通加密用户身份登录CloudHSM，检索密钥详细信息。这是由于CloudHSM管理员模式不能用于密钥检索等日常操作，日常检索密钥必须使用`crypto-user`级别的用户。

```shell
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username user01 --role crypto-user
```

输入密码后，登录完成。执行如下命令检索刚才创建的label是`new-master-key`的主密钥。

```shell
key list --filter attr.label=new-master-key
```

返回结果如下：

```shell
{
  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x0000000000000ca5",
        "attributes": {
          "label": "new-master-key"
        }
      }
    ],
    "total_key_count": 1,
    "returned_key_count": 1
  }
}
```

这里可以看到搜索结果，`label`标签是`new-master-key`的密钥对应的`key-reference`是`0x0000000000000ca5`，记录下来并代入下边的命令，查看详细属性。

```shell
key list --filter key-reference=0x0000000000000ca5 --verbose
```

这个命令会返回当前Key所有的属性。返回如下：

```shell
{
  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x0000000000000ca5",
        "key-info": {
          "key-owners": [
            {
              "username": "user01",
              "key-coverage": "full"
            }
          ],
          "shared-users": [],
          "key-quorum-values": {
            "manage-key-quorum-value": 0,
            "use-key-quorum-value": 0
          },
          "cluster-coverage": "full"
        },
        "attributes": {
          "key-type": "aes",
          "label": "new-master-key",
          "id": "0x",
          "check-value": "0xbe4119",
          "class": "secret-key",
          "encrypt": false,
          "decrypt": false,
          "token": true,
          "always-sensitive": true,
          "derive": false,
          "destroyable": true,
          "extractable": false,
          "local": true,
          "modifiable": true,
          "never-extractable": true,
          "private": true,
          "sensitive": true,
          "sign": true,
          "trusted": false,
          "unwrap": true,
          "verify": true,
          "wrap": true,
          "wrap-with-trusted": false,
          "key-length-bytes": 32
        }
      }
    ],
    "total_key_count": 1,
    "returned_key_count": 1
  }
}
```

可以看到当前属性`"trusted": false`。接下来要切换到管理员身份，为其设置信任。执行`quit`命令退出当前普通用户身份。

以管理员身份使用CloudHSM CLI登录：

```shell
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username admin --role admin
```

输入密码后，成为管理员权限，将如下命令中的`key-reference`替换为上文查询的结果。执行如下命令设置Trusted属性：

```shell
key set-attribute --filter key-reference=0x0000000000000ca5 --name trusted --value true
```

返回结果如下：

```shell
{
  "error_code": 0,
  "data": {
    "message": "Attribute set successfully"
  }
}
```

设置信任key属性完成。

### 4、生成Data Key并Wrap导出

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/WrapDemoStep2GenerateDataKeyAndWrap.java。

继续前边的操作，在已经设置要CloudHSM用户名和密码的环境变量的情况下，运行如下命令：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/wrap-demo-step-2-generate-data-key-and-wrap-1.0-SNAPSHOT.jar 
```

返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
Data Key创建成功！
Data Key已被wrap导出:
Wrapped Key (Base64): Elob/RRLYZDLZeKRsfhRmsWD162cnghK0PHL12tVIwC925xdacJwYg==
请将此wrapped key用于Step3
```

由此可以看到，在CloudHSM内生成了新的Data Key，并且使用`new-master-key`主密钥做了wrap导出。现在可将这段Wraped key传入下一个程序，执行unwrap测试。

### 5、在CloudHSM上以Unwrap方式导入Data Key并对数据加密

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/WrapDemoStep3UnwrapDataKeyAndEncryptd.java。

上一步生成了Data Key，并且Data Key被Wrap出来，以密文方式保存。现在可以把这个密文加入到代码`WrapDemoStep3UnwrapDataKeyAndEncryptd.java`中，然后重新构建并执行。

```shell
java -jar target/wrap-demo-step-3-unwrap-data-key-and-encryptd-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
Wrapped Key密文: Elob/RRLYZDLZeKRsfhRmsWD162cnghK0PHL12tVIwC925xdacJwYg==
Data Key已成功unwrap导入到CloudHSM
使用算法: AES/GCM/NoPadding
原始消息: Hello CloudHSM! This is a test message.
加密结果: AAAAAAAAAAAAAAAAVYpezkTKDpVki+ZjL1Te+Rspxl9aOoaM8U2Q5dTOL6CfA7mDuCJiTjCbJSkyj16fh9NayI628A==
Session结束，data key已从CloudHSM中释放
```

### 6、在CloudHSM上以Unwrap方式导入Data Key并对密文做解密

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/WrapDemoStep4UnwrapDataKeyAndDecryption.java。

上一步加密数据成功，下一步演示如何解密数据。首先用Wrapped Key的导入到CloudHSM，通过Unwrap操作恢复为Data key，并且传入要解密的密文，进行数据解密。解密之后，Data Key作为Session Key不长期保留在CloudHSM内，因此Session结束后直接释放。

```shell
java -jar target/wrap-demo-step-4-unwrap-data-key-and-decryption-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户 user01 连接到CloudHSM...
Wrapped Key密文: Elob/RRLYZDLZeKRsfhRmsWD162cnghK0PHL12tVIwC925xdacJwYg==
Step3的加密消息: IGdLOgFlzr5SLSZWBJmtd70P6aOtn7QiIAMdBPgYwKwxDvFQL/2NgU2aiZH7krexrIE8Dfg7rWDKMawvXl8Re1+yxw==
Data Key已成功unwrap导入到CloudHSM
使用算法: AES/GCM/NoPadding
Step3加密消息: IGdLOgFlzr5SLSZWBJmtd70P6aOtn7QiIAMdBPgYwKwxDvFQL/2NgU2aiZH7krexrIE8Dfg7rWDKMawvXl8Re1+yxw==
解密结果: Hello CloudHSM! This is a test message.
Session结束，data key已从CloudHSM中释放
```

由此可以看到，Unwrap后的Key解密成功。

## 三、使用非对称密钥和Unwrap机制实现私钥迁移到CloudHSM

### 1、私钥迁移背景

假设AWS云之外的受保护的位置有一个Private Key即被迁移的私钥，这个Private Key当前以明文形式存在，不过这个环境受到高度保护，明文是不允许离开这个环境的。现在，业务要求将这个Private Key从当前位置导入到海外的AWS CloudHSM加密机内部。由于受到明文不准离开保护范围的制约，需要有一种加密导入/导出机制来完成这个私钥迁移。

为此我们设计如下一种策略：

- 在AWS海外的CloudHSM生成一个非对称密钥叫做migration key，将private key私钥保存在CloudHSM加密机内，将public key公钥导出；
- 将上一步migration key的public key传输到AWS云之外受保护的环境内，用这个public key对被迁移的private key做加密，获得private key的密文，并将这个密文放到海外AWS云上可操作CloudHSM加密机的环境内（管理用虚拟机上）
- 在CloudHSM上执行Key unwrap操作，使用migration key的private key解密，将被迁移的key的密文解密，获得被迁移的private key明文，此时明文仅保存在CloudHSM加密机内，加密机外没有明文存在
- 上一步过程中，对这个private key设置属性，包括CloudHSM的禁止导出属性等，用于提高防护级别

现在进入代码示例。

### 2、在CloudHSM内生成Migration Key非对称密钥

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/MigrateProtectKeyStep1.java

执行如下命令创建Migration Key。这里创建非对称密钥用的是RSA4096。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/migrate-protect-key-step1-1.0-SNAPSHOT.jar
```

创建完毕返回如下：

```shell
使用用户: user01 连接到CloudHSM...
RSA-4096 密钥对创建成功！
密钥标签: migration-key
公钥算法: RSA
公钥已保存: ../openssl-key/migration-key-public.pem
```

此代码会在CloudHSM内生成非对称密钥，其中Private Key明文会保存在密码机内，Public Key会在保存到本机的`../openssl-keys/`目录下，文件名是`migration-key-public.pem`文件。

接下来使用CloudHSM CLI查看CloudHSM内的密钥。

```shell
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username user01 --role crypto-user
```

输入密码完成登录，执行如下命令查看刚导入的密钥详细属性。

```shell
key list --filter attr.label=migration-key-public --verbose
key list --filter attr.label=migration-key-private --verbose
```

查看密钥返回结果如下：

```shell
{
  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x0000000000001689",
        "attributes": {
          "label": "migration-key-private"
        }
      },
      {
        "key-reference": "0x0000000000002fdd",
        "attributes": {
          "label": "TestKeyForPlainTextExport"
        }
      },
      {
        "key-reference": "0x00000000000032cb",
        "attributes": {
          "label": "migration-key-public"
        }
      }
    ],
    "total_key_count": 3,
    "returned_key_count": 3
  }
}
```

由此生成migration key完成。

### 3、在AWS云外对被迁移的Private Key的明文做加密

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/MigrateProtectKeyStep2.java

现在我们使用一段Java代码模拟在AWS云外对被迁移的Private Key的明文做加密。注意，以下命令模拟的是AWS云外的操作，因此是不需要连接CloudHSM的。即便不使用Java代码，也可以使用其他加密库完成。这里使用的加密算法是RSA-OAEP-SHA512。

```shell
mvn clean package
java -jar target/migrate-protect-key-step2-1.0-SNAPSHOT.jar
```

返回如下：

```shell
步骤1: 转换 EC 私钥为 PKCS8 DER 格式...
PKCS8 DER 文件: ../openssl-key/ec_private_key_pkcs8.der
文件大小: 185 字节

步骤2: 使用 RSA-OAEP-SHA512 加密 PKCS8 密钥...
公钥文件: ../openssl-key/migration-key-public.pem

加密成功！
加密文件: ../openssl-key/ec_private_key.pem-encrypted
文件大小: 512 字节
```

由此在本地加密了被迁移的Private Key，加密后的密文保存在`../openssl-key/ec_private_key.pem-encrypted`文件中。

### 4、将被迁移的Private Key的密文通过unwrap导入到CloudHSM

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/MigrateProtectKeyStep3.java

现在调用CloudHSM，将刚才AWS云外加密好的密文导入到CloudHSM内做unwrap，从而解密出这个密钥的明文。运行如下命令：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/migrate-protect-key-step3-1.0-SNAPSHOT.jar
```

返回如下：

```shell
用用户: user01 连接到CloudHSM...
加密文件大小: 512 字节
找到 migration-key-private
EC 私钥已成功 unwrap 导入到 CloudHSM
密钥标签: imported-ec-key
密钥算法: EC
```

导入成功。此时登录CloudHSM CLI查看密钥：

```shell
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username user01 --role crypto-user
```

输入密码后登录成功，通过密钥标签查看密钥属性。在导入时候使用的标签是`imported-ec-key`。

```shell
key list --filter attr.label=imported-ec-key --verbose
```

返回结果可看到导入密钥成功。

```shell

  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x000000000000124b",
        "key-info": {
          "key-owners": [
            {
              "username": "user01",
              "key-coverage": "full"
            }
          ],
          "shared-users": [],
          "key-quorum-values": {
            "manage-key-quorum-value": 0,
            "use-key-quorum-value": 0
          },
          "cluster-coverage": "full"
        },
        "attributes": {
          "key-type": "ec",
          "label": "imported-ec-key",
          "id": "0x",
          "check-value": "0xd13f67",
          "class": "private-key",
          "encrypt": false,
          "decrypt": true,
          "token": true,
          "always-sensitive": false,
          "derive": false,
          "destroyable": true,
          "extractable": false,
          "local": false,
          "modifiable": true,
          "never-extractable": false,
          "private": true,
          "sensitive": true,
          "sign": true,
          "trusted": false,
          "unwrap": true,
          "verify": false,
          "wrap": false,
          "wrap-with-trusted": false,
          "key-length-bytes": 185,
          "ec-point": "0x0461048618eb4af2f42cb3ad76ccde9c8ff0d929bce69077e29b3c2cd58fbdb2d16e6124bbfe75f5308e4ada71225f03194398b95d3644f5d68da1082fb1bb6dd7593d67ceae88d2bd2d777ba258fb9c3e0b336547264713a31640bda9bf2ba100f96c",
          "curve": "secp384r1"
        }
      }
    ],
    "total_key_count": 1,
    "returned_key_count": 1
  }
}
```

## 四、不推荐有风险操作例子

注意：本文这里给出的例子不是AWS最佳实践，仅作为代码调试参考用。

### 1、导入Private Key密钥的明文到CloudHSM内

本场景说明：假设有一个在CloudHSM之外生成的密钥对，包含Public Key和Private Key。现在希望将Private Key的明文导入CloudHSM。

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/ImportPrivateKeyInPlainText.java

```shell
# 创建私钥
openssl ecparam -genkey -name secp384r1 -noout -out ec_private_key.pem
# 从私钥提取公钥
openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem
# 私钥从 SEC1 转 PKCS#8 格式：
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ec_sec1_key.pem -out ec_pkcs8_key.pem
# 查看私钥
cat ec_private_key.pem
```

由此在当前目录下获得`ec_private_key.pem`即私钥。

在Java代码中，调用的路径是`../openssl-key/ec_private_key.pem`，如果路径不一致请自行修改代码。启动Java程序：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/import-key-1.0-SNAPSHOT.jar
```

成功后返回结果如下。

```shell
=== CloudHSM EC私钥导入演示（从PEM文件）===
使用用户: user01 连接到CloudHSM...
密钥标签: myImportedPrivateKeyFromPEM

--- 开始从PEM文件导入EC私钥为永久密钥 ---
1. 读取PEM文件: ../openssl-key/ec_private_key.pem
2. 从SEC1格式提取私钥值...
   原始密钥字节长度: 48 字节
3. 创建KeyAttributesMap并设置属性...
4. 导入密钥到CloudHSM...
✅ EC私钥导入成功！

--- 验证导入的私钥 ---
✅ 永久密钥验证成功！
   签名长度: 102 字节
   密钥已永久存储在CloudHSM中

✅ EC私钥永久导入成功完成！
密钥已作为永久密钥存储在CloudHSM中，标签为: myImportedPrivateKeyFromPEM
```

可看到导入密钥成功。接下来使用CloudHSM CLI查看密钥。

```shell
/opt/cloudhsm/bin/cloudhsm-cli interactive
login --username user01 --role crypto-user
```

输入密码完成登录，执行如下命令查看刚导入的密钥详细属性。

```shell
key list --filter attr.label=myImportedPrivateKeyFromPEM --verbose
```

返回结果如下：

```shell
{
  "error_code": 0,
  "data": {
    "matched_keys": [
      {
        "key-reference": "0x0000000000002a29",
        "key-info": {
          "key-owners": [
            {
              "username": "user01",
              "key-coverage": "full"
            }
          ],
          "shared-users": [],
          "key-quorum-values": {
            "manage-key-quorum-value": 0,
            "use-key-quorum-value": 0
          },
          "cluster-coverage": "full"
        },
        "attributes": {
          "key-type": "ec",
          "label": "myImportedPrivateKeyFromPEM",
          "id": "0x",
          "check-value": "0xd13f67",
          "class": "private-key",
          "encrypt": false,
          "decrypt": true,
          "token": true,
          "always-sensitive": false,
          "derive": false,
          "destroyable": true,
          "extractable": false,
          "local": false,
          "modifiable": true,
          "never-extractable": false,
          "private": true,
          "sensitive": true,
          "sign": true,
          "trusted": false,
          "unwrap": true,
          "verify": false,
          "wrap": false,
          "wrap-with-trusted": false,
          "key-length-bytes": 185,
          "ec-point": "0x0461048618eb4af2f42cb3ad76ccde9c8ff0d929bce69077e29b3c2cd58fbdb2d16e6124bbfe75f5308e4ada71225f03194398b95d3644f5d68da1082fb1bb6dd7593d67ceae88d2bd2d777ba258fb9c3e0b336547264713a31640bda9bf2ba100f96c",
          "curve": "secp384r1"
        }
      }
    ],
    "total_key_count": 1,
    "returned_key_count": 1
  }
}
```

以上就是刚导入的这个密钥明文的详细属性。

### 2、密钥明文导出（不推荐）

本场景说明：假设有一个已经在CloudHSM内生成的密钥，现在希望将此密钥的明文导出。假设密钥的label是`myImportedPrivateKeyFromPEM`。在这种场景下，不使用Key Wrap机制、而是直接调用了key.getEncoded()方法获取密钥明文字节。这是CloudHSM JCE SDK提供的直接导出API。此方法不推荐，将明文导出CloudHSM有安全隐患，建议使用Key wrap机制将密钥加密封装后导出。

本章节代码见本文开头Github的：src/main/java/com/example/cloudhsm/

#### (1) 生成一个可用于导出的密钥

要从CloudHSM导出的密钥需要有`EXTRACTABLE=true`的标签。然而，已经创建好的密钥是不能直接修改标签的，因此CloudHSM的安全设计原则是密钥创建这一刻就决定了能否导出（无论是加密还是非加密），因此一旦创建好的密钥，不能修改。因此在本环节我们重新创建一个AES256密钥，并设置属性为可导出。

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/export-key-step1-1.0-SNAPSHOT.jar
```

返回结果如下。

```shell
使用用户: user01 连接到CloudHSM...
AES256密钥创建成功！
密钥标签: TestKeyForPlainTextExport
密钥算法: AES
EXTRACTABLE: true
```

由此在CloudHSM内创建好了标签为`TestKeyForPlainTextExport`的密钥。

#### (2) CloudHSM的Java SDK需要额外配置允许密钥导出

首先需要在JCE Provider SDK上做额外配置，允许密钥导出。注意是一次性配置，部署CloudHSM初始化阶段配置好，后续代码执行不需要此配置。

```shell
# 允许Java SDK密钥明文导出
sudo /opt/cloudhsm/bin/configure-jce --enable-clear-key-extraction-in-software
```
配置完成。

如果后续不需要使用密钥明文导出了，使用如下命令关闭。

```shell
# 禁用Java SDK密钥明文导出
sudo /opt/cloudhsm/bin/configure-jce --disable-clear-key-extraction-in-software
```

#### (3) 导出密钥

在Java代码中，密钥导出保存的路径是`../openssl-key/TestKeyForPlainTextExport.pem`，如果路径不存在会报错，请提前准备好目录。启动Java程序：

```shell
mvn clean package
export HSM_USER=user01
export HSM_PASSWORD=1qazxsw2
java -jar target/export-key-step2-1.0-SNAPSHOT.jar
```

返回结果如下：

```shell
使用用户: user01 连接到CloudHSM...

密钥导出成功！
密钥引用ID: 0x2fdd
密钥算法: AES
密钥格式: RAW
密钥长度: 32 字节
密钥明文 (Base64): QMGKO38wL/zcReifGktC2xP+oHSCbUc3HwxLZW3iWEQ=
密钥明文 (Hex): 40c18a3b7f302ffcdc45e89f1a4b42db13fea074826d47371f0c4b656de25844

PEM文件已保存: ../openssl-key/TestKeyForPlainTextExport.pem
```

导出时候需要注意密钥格式，例如某些场景下，原始密钥格式可能是SEC1 (EC PRIVATE KEY)，而导出后的密钥是PKCS#8 (PRIVATE KEY)，在PEM文本文件看起来是不相同的，但其实是同一个密钥。此时可执行：

```shell
openssl ec -in /home/ubuntu/environment/cloudhsm/openssl-key/ec_private_key_exported.pem -text -noout 2>&1 | grep -A5 "priv:"
```

分别对原始密钥和导出的密钥执行以上命令，即可确认导出的是否与原始文件一致。


## 五、参考文档

CloudHSM CLI下载

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/gs_cloudhsm_cli-install.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/gs_cloudhsm_cli-install.html)

CloudHSM 用户类型

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/understanding-users.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/understanding-users.html)

CloudHSM 硬件机能限制（密钥个数等）

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/limits.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/limits.html)

CloudHSM Performance性能限制

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/performance.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/performance.html)

CloudHSM JCE Provider SDK下载

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html)

HSM user permissions table for CloudHSM CLI

[https://docs.aws.amazon.com/cloudhsm/latest/userguide/user-permissions-table-chsm-cli.html](https://docs.aws.amazon.com/cloudhsm/latest/userguide/user-permissions-table-chsm-cli.html)

CloudHSM用户管理中的仲裁：

[https://docs.aws.amazon.com/zh_cn/cloudhsm/latest/userguide/quorum-auth-chsm-cli.html](https://docs.aws.amazon.com/zh_cn/cloudhsm/latest/userguide/quorum-auth-chsm-cli.html)

CloudHSM密钥管理中的仲裁：

[https://docs.aws.amazon.com/zh_cn/cloudhsm/latest/userguide/key-quorum-auth-chsm-cli.html](https://docs.aws.amazon.com/zh_cn/cloudhsm/latest/userguide/key-quorum-auth-chsm-cli.html)

</details>