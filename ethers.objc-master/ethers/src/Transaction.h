/**
 *  MIT License
 *
 *  Copyright (c) 2017 Richard Moore <me@ricmoo.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining
 *  a copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject to
 *  the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#import <Foundation/Foundation.h>

#import "Address.h"
#import "BigNumber.h"
#import "Hash.h"
#import "Signature.h"


/**
 *  Chain ID
 *
 *  As of EIP155, the chain ID can be used when signing requests to protect from
 *  replay attacks on other networks. This alters the internal structure of the
 *  payload that is hashed before signing the digest, so ChainIdAny is provided
 *  to continue using the legacy method of signing, but this also means the
 *  transaction is not safe against replays.
 *
 *  Note: ChainIdAny is NOT recommended
 *
 *  See: https://github.com/ethereum/EIPs/issues/155
 */

typedef NS_OPTIONS(NSInteger, ChainId)  {
    ChianIdAny = 0x00,
    ChainIdHomestead = 0x01,
    ChainIdMorden = 0x02,
    ChainIdRopsten = 0x03,
    ChainIdRinkeby = 0x04,
    ChainIdKovan = 0x2a,
    ChainIdPrivate = 0x0f,
    ChainIdBSCMain = 0x38,
    ChainIdBSCTest = 0x61,
    ChainIdHECMain = 0x80,
    ChainIdHECTest = 0xff,
    ChainIdPolygonMain = 0x89,
    ChainIdPolygonTEST = 80001,
    ChainIdHarmonyShard0Main = 1666600000,
    ChainIdHarmonyShard0Test = 1666700000,
    ChainIdHarmonyShard1Main = 1666600001,
    ChainIdHarmonyShard1Test = 1666700001,
    ChainIdHarmonyShard2Main = 1666600002,
    ChainIdHarmonyShard2Test = 1666700002,
    ChainIdHarmonyShard3Main = 1666600003,
    ChainIdHarmonyShard3Test = 1666700003
    //    ChainIdPrivate      = ChainIdHomestead,
};

extern NSString * _Nullable chainName(ChainId chainId);

//typedef unsigned long long Nonce;


@interface Transaction : NSObject

+ (nonnull instancetype)transaction;
+ (nonnull instancetype)transactionWithFromAddress: (nonnull Address*)fromAddress;

+ (nonnull instancetype)transactionWithData: (nonnull NSData*)transactionData;

@property (nonatomic, assign) NSUInteger nonce;

@property (nonatomic, strong, nonnull) BigNumber *gasPrice;
@property (nonatomic, strong, nonnull) BigNumber *gasLimit;

@property (nonatomic, strong, nullable) Address *toAddress;
@property (nonatomic, strong, nonnull) BigNumber *value;
@property (nonatomic, strong, nonnull) NSData *data;

@property (nonatomic, readonly, nullable) Signature *signature;

@property (nonatomic, readonly, nullable) Address *fromAddress;

@property (nonatomic, assign) ChainId chainId;

- (nonnull NSData*)serialize;

- (nonnull NSData*)unsignedSerialize;
- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s;

@property (nonatomic, readonly, nullable) Hash *transactionHash;

@end



@interface Transaction1559 : NSObject


+ (nonnull instancetype)transaction;
+ (nonnull instancetype)transactionWithFromAddress: (nonnull Address*)fromAddress;

+ (nonnull instancetype)transactionWithData: (nonnull NSData*)transactionData;

@property (nonatomic, assign) NSUInteger nonce;

@property (nonatomic, strong, nonnull) BigNumber *gasLimit;

@property (nonatomic, strong, nullable) Address *toAddress;
@property (nonatomic, strong, nonnull) BigNumber *value;
@property (nonatomic, strong, nonnull) NSData *data;

@property (nonatomic, readonly, nullable) Signature *signature;

@property (nonatomic, readonly, nullable) Address *fromAddress;

@property (nonatomic, assign) ChainId chainId;

@property (nonatomic, strong,nonnull) BigNumber *maxFeePerGas;
@property (nonatomic, strong,nonnull) BigNumber *maxPriorityFeePerGas;


- (nonnull NSData*)serialize;

- (nonnull NSData*)unsignedSerialize;
- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s;

@property (nonatomic, readonly, nullable) Hash *transactionHash;

@end




@interface HarmonyTransaction : NSObject

+ (nonnull instancetype)transaction;
+ (nonnull instancetype)transactionWithFromAddress: (nonnull Address*)fromAddress;
+ (nonnull instancetype)transactionWithData: (nonnull NSData*)transactionData;

@property (nonatomic, assign) NSUInteger nonce;

@property (nonatomic, strong, nonnull) BigNumber *gasPrice;
@property (nonatomic, strong, nonnull) BigNumber *gasLimit;

@property (nonatomic, strong, nullable) Address *toAddress;
@property (nonatomic, strong, nonnull) BigNumber *value;
@property (nonatomic, strong, nonnull) NSData *data;

@property (nonatomic, readonly, nullable) Signature *signature;

@property (nonatomic, readonly, nullable) Address *fromAddress;

@property (nonatomic, assign) ChainId chainId;

@property (nonatomic, assign) int shardId;
@property (nonatomic, assign) int toShardId;

- (Transaction *)convertToEth;

- (nonnull NSData*)serialize;
- (nonnull NSData*)unsignedSerialize;
- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s;

@property (nonatomic, readonly, nullable) Hash *transactionHash;

@end
