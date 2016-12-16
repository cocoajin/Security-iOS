//
//  NSData+KKSignVerify.h
//  SecurityiOS
//
//  Created by cocoa on 16/12/15.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/SecBase.h>


//主要使用PKCS1 方式的填充，最大签名数据长度为blockSize-11
//签名数据 一般签名，数据的HASH值；
//签名算法从ios5以后不再支持md5,md2
typedef enum : NSUInteger {
    SEC_PKCS1SHA1 = 2000,
    SEC_PKCS1SHA224,
    SEC_PKCS1SHA256,
    SEC_PKCS1SHA384,
    SEC_PKCS1SHA512,
} SEC_PKCS1_ALGORITHM;

@interface NSData (KKSignVerify)


/**
    根据不同的算法，签名数据，
 */
- (NSData *)signDataWith:(SecKeyRef)privateKey algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm;

/**
    验证签名数据
 */
- (BOOL)verifySignWith:(SecKeyRef)publicKey signData:(NSData *)signData algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm;



@end
