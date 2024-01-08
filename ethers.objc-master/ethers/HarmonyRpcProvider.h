//
//  HarmonyRpcProvider.h
//  ethers
//
//  Created by Leo on 2021/11/5.
//  Copyright © 2021 Ethers. All rights reserved.
//

#import <ethers/ethers.h>

NS_ASSUME_NONNULL_BEGIN

@interface HarmonyRpcProvider : ApiProvider
- (instancetype)initWithChainId: (ChainId)chainId url: (NSURL*)url;

@property (nonatomic, readonly) NSURL *url;
@end

NS_ASSUME_NONNULL_END
