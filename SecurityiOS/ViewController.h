//
//  ViewController.h
//  SecurityiOS
//
//  Created by cocoa on 16/12/14.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>


#define kRSA_KEY_SIZE 1024

@interface ViewController : UIViewController
{
    SecKeyRef publicKeyRef; //公钥
    SecKeyRef privateKeyRef;//私钥
}

@end

