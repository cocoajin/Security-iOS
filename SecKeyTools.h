//
//  SecKeyTools.h
//  SecurityiOS
//
//  Created by cocoa on 16/12/16.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/SecBase.h>

/**
        从文件中载入公钥和密钥，把密钥以文件形式放在手机里是不安全的；视业务场景定吧
 */
@interface SecKeyTools : NSObject


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

@end
