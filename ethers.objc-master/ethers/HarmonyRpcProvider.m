//
//  HarmonyRpcProvider.m
//  ethers
//
//  Created by Leo on 2021/11/5.
//  Copyright © 2021 Ethers. All rights reserved.
//

#import "HarmonyRpcProvider.h"
#import "SecureData.h"
#import "Utilities.h"

@interface Provider (private)

- (void)setBlockNumber: (NSInteger)blockNumber;

@end


#pragma mark -
#pragma mark - HarmonyRpcProvider

@implementation HarmonyRpcProvider {
    NSUInteger _requestCount;
    NSTimer *_poller;
}

- (instancetype)initWithChainId:(ChainId)chainId url:(NSURL *)url {
    self = [super initWithChainId:chainId];
    if (self) {
        _url = url;
        [self doPoll];
    }
    return self;
}

- (void)dealloc {
    [_poller invalidate];
}

- (void)reset {
    [super reset];
    [self doPoll];
}


#pragma mark - Polling

- (void)doPoll {
    [[self getBlockNumber] onCompletion:^(IntegerPromise *promise) {
        if (promise.result) {
            [self setBlockNumber:promise.value];
        }
    }];
}

- (void)startPolling {
    if (self.polling) { return; }
    [super startPolling];
    _poller = [NSTimer scheduledTimerWithTimeInterval:14.0f target:self selector:@selector(doPoll) userInfo:nil repeats:YES];
}

- (void)stopPolling {
    if (!self.polling) { return; }
    [super stopPolling];
    [_poller invalidate];
    _poller = nil;
}


#pragma mark - Methods

- (id)sendMethod: (NSString*)method params: (NSObject*)params fetchType: (ApiProviderFetchType)fetchType {
    
    NSDictionary *request = @{
        @"jsonrpc": @"2.0",
        @"method": method,
        @"id": @(42),
        @"params": params,
    };
    
    NSError *error = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:request options:0 error:&error];
    
    if (error) {
        NSDictionary *userInfo = @{@"reason": @"invalid JSON values", @"error": error};
        return [Promise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:userInfo]];
    }
    
    NSObject* (^processResponse)(NSDictionary*) = ^NSObject*(NSDictionary *response) {
        NSDictionary *rpcError = [response objectForKey:@"error"];
        if (rpcError) {
            NSDictionary *userInfo = @{@"reason": [NSString stringWithFormat:@"%@", [rpcError objectForKey:@"message"]]};
            return [NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorBadResponse userInfo:userInfo];
        }
        
        NSObject *result = [response objectForKey:@"result"];
        if (!result) {
            NSDictionary *userInfo = @{@"reason": @"invalid result"};
            return [NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorBadResponse userInfo:userInfo];
        }
        return result; //coerceValue(result, fetchType);
    };
    
    return [self promiseFetchJSON:_url
                             body:body
                        fetchType:fetchType
                          process:processResponse];
}

- (BigNumberPromise*)getBalance:(Address *)address blockTag:(BlockTag)blockTag {
    NSObject *tag = getBlockTag(blockTag);
    
    if (!address || !tag ) {
        return [BigNumberPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getBalance"
                     params:@[ address.checksumAddress, tag ]
                  fetchType:ApiProviderFetchTypeBigNumberHexString];
}

- (IntegerPromise*)getTransactionCount:(Address *)address blockTag:(BlockTag)blockTag {
    NSObject *tag = getBlockTag(blockTag);
    
    if (!address || !tag) {
        return [IntegerPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getTransactionCount"
                     params:@[ address.checksumAddress, tag ]
                  fetchType:ApiProviderFetchTypeIntegerHexString];
}

- (DataPromise*)getCode: (Address*)address {
    if (!address) {
        return [DataPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getCode"
                     params:@[ address.checksumAddress , @"latest"]
                  fetchType:ApiProviderFetchTypeData];
}

- (IntegerPromise*)getBlockNumber {
    return [self sendMethod:@"hmy_blockNumber" params:@[] fetchType:ApiProviderFetchTypeIntegerHexString];
}

- (BigNumberPromise*)getGasPrice {
    return [self sendMethod:@"hmy_gasPrice" params:@[] fetchType:ApiProviderFetchTypeBigNumberHexString];
}

- (DataPromise*)call:(Transaction *)transaction {
    if (!transaction || !transaction.toAddress) {
        return [DataPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_call"
                     params:@[ transactionObject(transaction), @"latest" ]
                  fetchType:ApiProviderFetchTypeData];
}

- (BigNumberPromise*)estimateGas:(Transaction *)transaction {
    if (!transaction) {
        return [BigNumberPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_estimateGas"
                     params:@[ transactionObject(transaction)]
                  fetchType:ApiProviderFetchTypeBigNumberHexString];
}

- (HashPromise*)sendTransaction:(NSData *)signedTransaction {
    if (!signedTransaction) {
        return [HashPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_sendRawTransaction"
                     params:@[ [SecureData dataToHexString:signedTransaction] ]
                  fetchType:ApiProviderFetchTypeHash];
}

- (BlockInfoPromise*)getBlockByBlockTag:(BlockTag)blockTag {
    NSObject *blockTagName = getBlockTag(blockTag);
    if (!blockTagName) {
        return [BlockInfoPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getBlockByNumber"
                     params:@[blockTagName, @(NO)]
                  fetchType:ApiProviderFetchTypeBlockInfo];
}

- (BlockInfoPromise*)getBlockByBlockHash:(Hash *)blockHash {
    if (!blockHash) {
        return [BlockInfoPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getBlockByHash"
                     params:@[blockHash.hexString, @(NO)]
                  fetchType:ApiProviderFetchTypeBlockInfo];
}

- (TransactionInfoPromise*)getTransaction:(Hash *)transactionHash {
    if (!transactionHash) {
        return [TransactionInfoPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getTransactionByHash"
                     params:@[transactionHash.hexString]
                  fetchType:ApiProviderFetchTypeTransactionInfo];
}

- (HashPromise*)getStorageAt:(Address *)address position:(BigNumber *)position {
    if (!address) {
        return [HashPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
    }
    
    return [self sendMethod:@"hmy_getStorageAt"
                     params:@[ address.checksumAddress, stripHexZeros([position hexString]), @"latest" ]
                  fetchType:ApiProviderFetchTypeHash];
}

- (ArrayPromise *)getTokenBalance:(Address *)address {
    return [ArrayPromise rejected:[NSError errorWithDomain:ProviderErrorDomain code:ProviderErrorInvalidParameters userInfo:@{}]];
}

#pragma mark - NSObject

- (NSString*)description {
    return [NSString stringWithFormat:@"<JsonRpcProvider chainId=%d url=%@>", self.chainId, _url];
}

@end
