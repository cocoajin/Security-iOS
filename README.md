# Security-iOS

封装了一些iOS上使用的NSData分类，主要用于 `RSA加密`,`AES加密`,`数据签名`,`签名校验`,`MD5 SHA1 SHA256 常用hash`等工具。

主要使用的是iOS上 `Security.framework` 和 `CommonCrypto` 接口

支持iOS2.0+开发


## md5,sha1,sha256常用hash

 接口文件和源码 `NSData+KKHASH.h`,`NSData+KKHASH.m`

支持的hash算法有

```objective-c
typedef enum : NSUInteger {
    //md2 16字节长度
    CCDIGEST_MD2 = 1000,
    //md4 16字节长度
    CCDIGEST_MD4,
    //md5 16字节长度
    CCDIGEST_MD5,
    //sha1 20字节长度
    CCDIGEST_SHA1,
    //SHA224 28字节长度
    CCDIGEST_SHA224,
    //SHA256 32字节长度
    CCDIGEST_SHA256,
    //SHA384 48字节长度
    CCDIGEST_SHA384,
    //SHA512 64字节长度
    CCDIGEST_SHA512,
} CCDIGESTAlgorithm;
```

调用接口

```objective-c
/**
    计算数据的hash值，根据不同的算法
 */
- (NSData *)hashDataWith:(CCDIGESTAlgorithm )ccAlgorithm;


/**
    返回 hex string的 data
 */
- (NSString *)hexString;
```

调用示例

```objective-c
//测试哈希函数
- (void)testKKHASHTools
{
    //以下结果由openssl dtsg 命令得出的结果，并和这里相比对
    NSString *tpath = [[NSBundle mainBundle] pathForResource:@"src.txt" ofType:nil];
    NSData *test = [NSData dataWithContentsOfFile:tpath];
    NSLog(@"%@",[[test hashDataWith:CCDIGEST_MD2] hexString]);
    if([[[test hashDataWith:CCDIGEST_MD4] hexString] isEqualToString:@"a695ea9f14a89c4e82ca5cf52a28d45d"])
    {
        NSLog(@"MD4 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_MD5] hexString] isEqualToString:@"781e5e245d69b566979b86e28d23f2c7"])
    {
        NSLog(@"MD5 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA1] hexString] isEqualToString:@"87acec17cd9dcd20a716cc2cf67417b71c8a7016"])
    {
        NSLog(@"SHA1 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA224] hexString] isEqualToString:@"f28ad8ecd48ba6f914c114821685ad08f0d6103649ff156599a90426"])
    {
        NSLog(@"SHA224 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA256] hexString] isEqualToString:@"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"])
    {
        NSLog(@"SHA256 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA384] hexString] isEqualToString:@"90ae531f24e48697904a4d0286f354c50a350ebb6c2b9efcb22f71c96ceaeffc11c6095e9ca0df0ec30bf685dcf2e5e5"])
    {
        NSLog(@"SHA384 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA512] hexString] isEqualToString:@"bb96c2fc40d2d54617d6f276febe571f623a8dadf0b734855299b0e107fda32cf6b69f2da32b36445d73690b93cbd0f7bfc20e0f7f28553d2a4428f23b716e90"])
    {
        NSLog(@"SHA512 TEST PASS");
    }

}
```

## AES 加密解密

接口文件和源码 `NSData+KKAES.h`,`NSData+KKAES.m`

支持AES cbc,ecb两种模式，默认使用的填充方式 `kCCOptionPKCS7Padding`.
可以参考更多 [iOS CommonCrypto 对称加密 AES ecb,cbc](http://www.cnblogs.com/cocoajin/p/6150203.html)

主要接口

```objective-c
/**
    AES cbc 模式加密，
    @key 长度16字节，24字节，32字节
    @iv 16字节
 */
- (NSData *)AES_CBC_EncryptWith:(NSData *)key iv:(NSData *)iv;

/**
    AES cbc 模式解密，
    @key 长度16字节，24字节，32字节
    @iv 16字节
 */
- (NSData *)AES_CBC_DecryptWith:(NSData *)key iv:(NSData *)iv;

/**
    AES ecb 模式加密，
    @key 长度16字节，24字节，32字节
 */
- (NSData *)AES_ECB_EncryptWith:(NSData *)key;

/**
    AES ecb 模式解密，
    @key 长度16字节，24字节，32字节
 */
- (NSData *)AES_ECB_DecryptWith:(NSData *)key;
```

调用示例

```objective-c
    NSData *key16 = [@"0123456789123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key24 = [@"012345678901234567891234" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key32 = [@"01234567890123456789012345678912" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv16 = [@"0123456789654321" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *srcData = [@"this is src test data" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData);
    
    
    
    NSData *dec16 = [[srcData AES_CBC_EncryptWith:key16 iv:iv16] AES_CBC_DecryptWith:key16 iv:iv16];
    if (memcmp(srcData.bytes, dec16.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_16 PASS");
    }
    
    
    NSData *dec24 = [[srcData AES_CBC_EncryptWith:key24 iv:iv16] AES_CBC_DecryptWith:key24 iv:iv16];
    if (memcmp(srcData.bytes, dec24.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_24 PASS");
    }
    
    
    NSData *dec32 = [[srcData AES_CBC_EncryptWith:key32 iv:iv16] AES_CBC_DecryptWith:key32 iv:iv16];
    if (memcmp(srcData.bytes, dec32.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_32 PASS");
    }
    
    
    
    
    NSData *edec16 = [[srcData AES_ECB_EncryptWith:key16] AES_ECB_DecryptWith:key16];
    if (memcmp(srcData.bytes, edec16.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_16 PASS");
    }
    
    
    NSData *edec24 = [[srcData AES_ECB_EncryptWith:key24] AES_ECB_DecryptWith:key24];
    if (memcmp(srcData.bytes, edec24.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_24 PASS");
    }
    
    
    NSData *edec32 = [[srcData AES_ECB_EncryptWith:key32] AES_ECB_DecryptWith:key32];
    if (memcmp(srcData.bytes, edec32.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_32 PASS");
    }
```


## RSA 加密解密

接口和源码 `NSData+KKRSA.h`,`NSData+KKRSA.m`

支持的RSA密钥位数：512,768,1024,2048等;
可以参考更多 [iOS使用Security.framework进行RSA 加密解密签名和验证签名](http://www.cnblogs.com/cocoajin/p/6183443.html)

支持的填充方式

```objective-c
//分组加密，支持最大的加密块为 block 和填充方式有关
typedef enum : NSUInteger {
    //不填充，最大数据块为 blockSize
    RSAPaddingNONE,
    //填充方式pkcs1,最大数据块为 blockSize -11
    RSAPaddingPKCS1,
    //填充方式OAEP, 最大数据块为 blockSize -42
    RSAPaddingOAEP,
} RSAPaddingTYPE;
```

调用接口

```objective-c
/**
    公钥加密
 */
- (NSData *)RSAEncryptWith:(SecKeyRef )publicKey paddingType:(RSAPaddingTYPE )pdType;

/**
    私钥解密
 */
- (NSData *)RSADecryptWith:(SecKeyRef )privateKey paddingType:(RSAPaddingTYPE )pdType;
```

调用示例

```objective-c
//生成RSA密钥对，公钥和私钥，支持的SIZE有
// sizes for RSA keys are: 512, 768, 1024, 2048.
- (void)generateRSAKeyPair:(int )keySize
{
    if (publicKeyRef) {
        return;
    }
    OSStatus ret = 0;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    ret = SecKeyGeneratePair((CFDictionaryRef)@{(id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,(id)kSecAttrKeySizeInBits:@(keySize)}, &publicKeyRef, &privateKeyRef);
    NSAssert(ret==errSecSuccess, @"密钥对生成失败：%d",ret);
    
    NSLog(@"%@",publicKeyRef);
    NSLog(@"%@",privateKeyRef);
    NSLog(@"max size:%lu",SecKeyGetBlockSize(privateKeyRef));
    
}

    //生成密钥对
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    
    NSData *srcData = [@"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128
    NSData *decData = [[srcData RSAEncryptWith:publicKeyRef paddingType:RSAPaddingNONE] RSADecryptWith:privateKeyRef paddingType:RSAPaddingNONE];
    
    if (memcmp(srcData.bytes, decData.bytes, srcData.length)==0) {
        NSLog(@"RSA RSAPaddingNONE TEST PASS");
    }
    
    
    NSData *srcData2 = [@"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128-11 117
    NSData *decData2 = [[srcData2 RSAEncryptWith:publicKeyRef paddingType:RSAPaddingPKCS1]
                        RSADecryptWith:privateKeyRef paddingType:RSAPaddingPKCS1];
    
    if (memcmp(srcData2.bytes, decData2.bytes, srcData2.length)==0) {
        NSLog(@"RSA RSAPaddingPKCS1 TEST PASS");
    }
    
    
    NSData *srcData3 = [@"01234567890123456789012345678901234567890123456789012345678901234567890123456789123456" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128-42 86
    NSData *decData3 = [[srcData3 RSAEncryptWith:publicKeyRef paddingType:RSAPaddingOAEP] RSADecryptWith:privateKeyRef paddingType:RSAPaddingOAEP];
    
    if (memcmp(srcData3.bytes, decData3.bytes, srcData3.length)==0) {
        NSLog(@"RSA RSAPaddingOAEP TEST PASS");
    }
```


## RSA签名验证签名

接口文件和源码 `NSData+KKSignVerify.h`,`NSData+KKSignVerify.m`

数据签名一般签名数据的hash值，配合上面的HASH函数使用

支持的签名算法

```objective-c
//主要使用PKCS1 方式的填充，最大签名数据长度为blockSize-11
//签名算法从ios5以后不再支持md5,md2
typedef enum : NSUInteger {
    SEC_PKCS1SHA1 = 2000,
    SEC_PKCS1SHA224,
    SEC_PKCS1SHA256,
    SEC_PKCS1SHA384,
    SEC_PKCS1SHA512,
} SEC_PKCS1_ALGORITHM;
```

主要接口

```objective-c
/**
    根据不同的算法，签名数据，
 */
- (NSData *)signDataWith:(SecKeyRef)privateKey algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm;

/**
    验证签名数据
 */
- (BOOL)verifySignWith:(SecKeyRef)publicKey signData:(NSData *)signData algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm;
```

调用示例

```objective-c
		//生成RSA密钥对，
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    
    NSString *tpath = [[NSBundle mainBundle] pathForResource:@"src.txt" ofType:nil];
    NSData *ttDt = [NSData dataWithContentsOfFile:tpath];
    NSData *sha1dg = [ttDt hashDataWith:CCDIGEST_MD4];
    

    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA1] algorithm:SEC_PKCS1SHA1]) {
        NSLog(@"SIGN-VERIFY sha1 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA224] algorithm:SEC_PKCS1SHA224]) {
        NSLog(@"SIGN-VERIFY sha224 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA256] algorithm:SEC_PKCS1SHA256]) {
        NSLog(@"SIGN-VERIFY sha256 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA384] algorithm:SEC_PKCS1SHA384]) {
        NSLog(@"SIGN-VERIFY sha384 PASS");
    }
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA512] algorithm:SEC_PKCS1SHA512]) {
        NSLog(@"SIGN-VERIFY sha512 PASS");
    }
```

## RSA密钥管理

接口文件和源码 `SecKeyTools.h`,`SecKeyTools.m`

主要用于读取密钥文件中的密钥，如从证书中读取公钥，从p12文件中读取私钥等操作；
RSA相关的密钥放在手机上是不安全的，但是也没有绝对的安全，视业务情况来定吧。

主要接口

```objective-c

/**
    从x509 cer证书中读取公钥
 */
+ (SecKeyRef )publicKeyFromCer:(NSString *)cerFile;


/**
    从 p12 文件中读取私钥，一般p12都有密码
 */
+ (SecKeyRef )privateKeyFromP12:(NSString *)p12File password:(NSString *)pwd;


/**
    iOS 10 上可用如下接口SecKeyCreateWithData 从pem文件中读取私钥或公钥
 */
+ (SecKeyRef )publicKeyFromPem:(NSString *)pemFile keySize:(size_t )size;

+ (SecKeyRef )privaKeyFromPem:(NSString *)pemFile keySize:(size_t )size;
```

调用示例

```objective-c
    NSString *cerPA = [[NSBundle mainBundle] pathForResource:@"CPPUB.cer" ofType:nil];
    NSString *p12PA = [[NSBundle mainBundle] pathForResource:@"CPPRI.p12" ofType:nil];
    
    SecKeyRef pubkey = [SecKeyTools publicKeyFromCer:cerPA];
    SecKeyRef prikey = [SecKeyTools privateKeyFromP12:p12PA password:@"test"];

    NSLog(@"%@",pubkey);
    NSLog(@"%@",prikey);
    
    NSLog(@"%lu",SecKeyGetBlockSize(prikey));
    
    
    NSData *srcData = [@"0123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData);
    NSData *encDT = [srcData RSAEncryptWith:pubkey paddingType:RSAPaddingPKCS1];
    NSData *decDT = [encDT RSADecryptWith:prikey paddingType:RSAPaddingPKCS1];
    NSLog(@"%@",decDT);
    
    
    
    NSString *pripem = [[NSBundle mainBundle] pathForResource:@"private.pem" ofType:nil];
    NSString *pubpem = [[NSBundle mainBundle] pathForResource:@"public.pem" ofType:nil];
    SecKeyRef pubKK = [SecKeyTools publicKeyFromPem:pubpem keySize:kRSA_KEY_SIZE];
    SecKeyRef priKK = [SecKeyTools privaKeyFromPem:pripem keySize:kRSA_KEY_SIZE];
    NSLog(@"%@",pubKK);
    NSLog(@"%@",priKK);
    
    NSLog(@"%lu",SecKeyGetBlockSize(priKK));
    NSData *srcData2 = [@"0123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData2);
    NSData *encDT2 = [srcData2 RSAEncryptWith:pubKK paddingType:RSAPaddingPKCS1];
    NSData *decDT2 = [encDT2 RSADecryptWith:priKK paddingType:RSAPaddingPKCS1];
    NSLog(@"%@",decDT2);
```


## 其他


- 密钥对的生成

```objective-c
//生成RSA密钥对，公钥和私钥，支持的SIZE有
// sizes for RSA keys are: 512, 768, 1024, 2048.
- (void)generateRSAKeyPair:(int )keySize
{
    if (publicKeyRef) {
        return;
    }
    OSStatus ret = 0;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    ret = SecKeyGeneratePair((CFDictionaryRef)@{(id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,(id)kSecAttrKeySizeInBits:@(keySize)}, &publicKeyRef, &privateKeyRef);
    NSAssert(ret==errSecSuccess, @"密钥对生成失败：%d",ret);
    
    NSLog(@"%@",publicKeyRef);
    NSLog(@"%@",privateKeyRef);
    NSLog(@"max size:%lu",SecKeyGetBlockSize(privateKeyRef));
    
}
```

- RSA上几种填充方式的区别

```objective-c
/** 三种填充方式区别
 kSecPaddingNone      = 0,   要加密的数据块大小<＝SecKeyGetBlockSize的大小，如这里128
 kSecPaddingPKCS1     = 1,   要加密的数据块大小<=128-11
 kSecPaddingOAEP      = 2,   要加密的数据块大小<=128-42
  密码学中的设计原则，一般用RSA来加密 对称密钥，用对称密钥加密大量的数据
  非对称加密速度慢，对称加密速度快
 */
```

- 示例工程 `SecurityiOS.xcodeproj`


