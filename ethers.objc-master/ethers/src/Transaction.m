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

#import "Transaction.h"

#include "ecdsa.h"
#include "secp256k1.h"

#import "Account.h"
#import "RLPSerialization.h"
#import "SecureData.h"
#import "Utilities.h"

static NSErrorDomain ErrorDomain = @"io.ethers.TransactionError";

static NSData *stripDataZeros(NSData *data) {
    const char *bytes = data.bytes;
    NSUInteger offset = 0;
    while (offset < data.length && bytes[offset] == 0) { offset++; }
    return [data subdataWithRange:NSMakeRange(offset, data.length - offset)];
}

static NSData *dataWithByte(NSInteger value) {
    BigNumber *t = [BigNumber bigNumberWithInteger:value];
    
    NSLog(@"v ===== %@",t.hexString);
    return t.data;
    //return [NSMutableData dataWithBytes:&value length:1];
}


NSString *chainName(ChainId chainId) {
    switch (chainId) {
        case ChainIdHomestead:  return @"homestead";
        case ChainIdMorden:     return @"morden";
        case ChainIdRopsten:    return @"ropsten";
        case ChainIdRinkeby:    return @"rinkeby";
        case ChainIdKovan:      return @"kovan";
        default:
            return @"TestNet";
            break;
    }
    return nil;
}

static NSData *NullData = nil;


#pragma mark -
#pragma mark - Signature

@interface Signature (private)

+ (instancetype)signatureWithData: (NSData*)data v:(int)v;

@end


#pragma mark -
#pragma mark - Transaction

@implementation Transaction

#pragma mark - Life-Cycle

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithFromAddress: (Address*)fromAddress {
    self = [self init];
    if (self) {
        _fromAddress = fromAddress;
    }
    return self;
}

+ (instancetype)transaction {
    return [[Transaction alloc] init];
}

+ (instancetype)transactionWithFromAddress:(Address*)fromAddress {
    return [[Transaction alloc] initWithFromAddress:fromAddress];
}

+ (instancetype)transactionWithData: (NSData*)transactionData {
    
    // Thinking out loud: Is there ANY difference between a transaction without a gasPrice
    // and one with a gasPrice of zero? If not, we should instantiate BigNumbers for
    // gasPrice, gasLimit, value and NSData for data
    
    // Decode the RLP
    NSError *error = nil;
    NSArray *raw = (NSArray*)[RLPSerialization objectWithData:transactionData error:&error];
    if (error || ![raw isKindOfClass:[NSArray class]]) { return nil; }
    
    if (raw.count != 9) { return nil; }
    
    // Check that every item is data (and not a nested array)
    for (NSData *item in raw) {
        if (![item isKindOfClass:[NSData class]]) {
            return nil;
        }
    }
    
    Transaction *transaction = [Transaction transaction];
    
    {
        BigNumber *nonce = [BigNumber bigNumberWithData:[raw objectAtIndex:0]];
        if (!nonce.isSafeUnsignedIntegerValue) {
            NSLog(@"WARNING: Nonce is out of range (%@)", nonce);
        }
        transaction.nonce = [nonce unsignedIntegerValue];
    }
    
    {
        NSData *gasPrice = [raw objectAtIndex:1];
        if (gasPrice.length > 32) {
            return nil;
        } else {
            transaction.gasPrice = [BigNumber bigNumberWithData:gasPrice];
        }
    }
    
    {
        NSData *gasLimit = [raw objectAtIndex:2];
        if (gasLimit.length > 32) {
            return nil;
        } else {
            transaction.gasLimit = [BigNumber bigNumberWithData:gasLimit];
        }
    }
    
    {
        NSData *toAddress = [raw objectAtIndex:3];
        if (toAddress.length) {
            transaction.toAddress = [Address addressWithData:toAddress];
            if (!transaction.toAddress) { return nil; }
        }
    }
    
    {
        NSData *value = [raw objectAtIndex:4];
        if (value.length > 32) {
            return nil;
        } else {
            transaction.value = [BigNumber bigNumberWithData:value];
        }
    }
    
    transaction.data = [raw objectAtIndex:5];
    
    {
        NSData *vObject = [raw objectAtIndex:6];
        if (vObject.length > 1) { return nil; }
        
        int v = 0;
        if (vObject.length == 1) {
            [vObject getBytes:&v range:NSMakeRange(0, 1)];
        }
        
        NSData *r = [raw objectAtIndex:7], *s = [raw objectAtIndex:8];;
        if (r.length > 32 || s.length > 32) { return nil; }
        
        NSMutableData *data = [NSMutableData dataWithLength:64];
        memset(data.mutableBytes, 0, 64);
        
        if (r.length) {
            [r getBytes:&data.mutableBytes[32 - r.length] range:NSMakeRange(0, r.length)];
        }
        
        if (s.length) {
            [s getBytes:&data.mutableBytes[64 - s.length] range:NSMakeRange(0, s.length)];
        }
        
        [transaction verifySignatureData:data v:v];
    }
    
    
    return transaction;
}


#pragma mark - Getters (prevent nil)

- (BigNumber*)gasLimit {
    if (!_gasLimit) { return [BigNumber constantZero]; }
    return _gasLimit;
}

- (BigNumber*)gasPrice {
    if (!_gasPrice) { return [BigNumber constantZero]; }
    return _gasPrice;
}

- (BigNumber*)value {
    if (!_value) { return [BigNumber constantZero]; }
    return _value;
}

- (NSData*)data {
    if (!_data) { return NullData; }
    return _data;
}


#pragma mark - Signature

- (void)_setSignature: (Signature*)signature {
    _signature = signature;
}

- (void)sign:(Account *)account {
    if (account) {
        NSMutableArray *raw = [self _packBasic];
        if (_chainId) {
            [raw addObject:dataWithByte(_chainId)];
            [raw addObject:NullData];
            [raw addObject:NullData];
        }
        
        NSError *error = nil;
        NSData *digest = [SecureData KECCAK256:[RLPSerialization dataWithObject:raw error:&error]];
        _fromAddress = account.address;
        _signature = [account signDigest:digest];
        
    } else {
        _fromAddress = nil;
        _signature = nil;
    }
}

- (void)verifySignatureData: (NSData*)signatureData v: (int)v {
    _signature = [Signature signatureWithData:signatureData v:v];
    
    // Use an int so we can detect underflow
    NSInteger chainId = (v - 35) / 2;
    if (chainId < 0) { chainId = 0; }
    
    _chainId = chainId;
    
    NSMutableArray *raw = [self _packBasic];
    if (_chainId) {
        [raw addObject:dataWithByte(_chainId)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    NSData *digest = [SecureData KECCAK256:[RLPSerialization dataWithObject:raw error:nil]];
    
    SecureData *publicKey = [SecureData secureDataWithLength:65];
    
    if (_chainId) {
        v -= (_chainId * 2 + 8);
    }
    
    int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, signatureData.bytes, digest.bytes, v - 27);
    if (!failed) {
        _fromAddress = [Address addressWithData:[[[publicKey subdataFromIndex:1] KECCAK256] subdataFromIndex:12].data];
    }
}


#pragma mark - Serialization

- (NSMutableArray*)_packBasic {
    
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:9];
    
    {
        NSData *nonceData = stripDataZeros(convertIntegerToData(self.nonce));
        if (nonceData.length > 32) { return nil; }
        [result addObject:nonceData];
    }
    
    if (self.gasPrice) {
        NSData *gasPriceData = stripDataZeros([SecureData hexStringToData:[self.gasPrice hexString]]);
        if (gasPriceData.length > 32) { return nil; }
        [result addObject:gasPriceData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.gasLimit) {
        NSData *gasLimitData = stripDataZeros([SecureData hexStringToData:[self.gasLimit hexString]]);
        if (gasLimitData.length > 32) { return nil; }
        [result addObject:gasLimitData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.toAddress) {
        [result addObject:self.toAddress.data];
    } else {
        [result addObject:NullData];
    }
    
    if (self.value) {
        NSData *valueData = stripDataZeros([SecureData hexStringToData:[self.value hexString]]);
        if (valueData.length > 32) { return nil; }
        [result addObject:valueData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.data) {
        [result addObject:self.data];
    } else {
        [result addObject:NullData];
    }
    
    
    
    return result;
}

- (NSData*)serialize {
    NSMutableArray *raw = [self _packBasic];
    
    if (_signature) {
        NSInteger v = 27 + self.signature.v;
        NSLog(@"%ld sig v====%ld",v);
        
        if (_chainId) { v += _chainId * 2 + 8; }
        
        [raw addObject:dataWithByte(v)];
        [raw addObject:stripDataZeros(self.signature.r)];
        [raw addObject:stripDataZeros(self.signature.s)];
        
    } else {
        [raw addObject:dataWithByte(_chainId ? _chainId: 28)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    return [RLPSerialization dataWithObject:raw error:nil];
}

- (NSData*)unsignedSerialize {
    NSMutableArray *raw = [self _packBasic];
    
    if (_chainId) {
        [raw addObject:dataWithByte(_chainId)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    return [RLPSerialization dataWithObject:raw error:nil];
}

- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s {
    NSMutableData *publicKey = [NSMutableData dataWithLength:65];
    
    NSMutableData *sig = [r mutableCopy];
    [sig appendData:s];
    
    NSData *digest = [SecureData KECCAK256:[self unsignedSerialize]];
    
    for (uint8_t recid = 0; recid <= 3; recid++) {
        int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, sig.bytes, digest.bytes, recid);
        if (!failed) {
            _signature = [Signature signatureWithData:[NSData dataWithData:sig] v:recid];
            return;
        }
    }
}

- (Hash*)transactionHash {
    if (!_signature) { return nil; }
    return [Hash hashWithData:[SecureData KECCAK256:[self serialize]]];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    Transaction *transaction = [Transaction transactionWithFromAddress:self.fromAddress];
    transaction.nonce = self.nonce;
    transaction.gasPrice = [self.gasPrice copy];
    transaction.gasLimit = [self.gasLimit copy];
    transaction.toAddress = self.toAddress;
    transaction.value = [self.value copy];
    transaction.data = [self.data copy];
    transaction.chainId = self.chainId;
    [transaction _setSignature:_signature];
    
    return transaction;
}


#pragma mark - NSObject

- (NSString*)description {
    return [NSString stringWithFormat:@"<Transaction to=%@ from=%@ nonce=%d gasPrice=%@ gasLimit=%@ value=%@ data=%@ chainId=%d signature=%@>",
            self.toAddress, self.fromAddress, (int)self.nonce, [self.gasPrice decimalString], [self.gasLimit decimalString],
            [self.value decimalString], [SecureData dataToHexString:self.data], _chainId, _signature];
}

@end


@implementation Transaction1559

#pragma mark - Life-Cycle

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithFromAddress: (Address*)fromAddress {
    self = [self init];
    if (self) {
        _fromAddress = fromAddress;
    }
    return self;
}

+ (instancetype)transaction {
    return [[Transaction1559 alloc] init];
}

+ (instancetype)transactionWithFromAddress:(Address*)fromAddress {
    return [[Transaction1559 alloc] initWithFromAddress:fromAddress];
}

+ (instancetype)transactionWithData: (NSData*)transactionData {
    
    // Thinking out loud: Is there ANY difference between a transaction without a gasPrice
    // and one with a gasPrice of zero? If not, we should instantiate BigNumbers for
    // gasPrice, gasLimit, value and NSData for data
    
    // Decode the RLP
    NSError *error = nil;
    NSArray *raw = (NSArray*)[RLPSerialization objectWithData:transactionData error:&error];
    if (error || ![raw isKindOfClass:[NSArray class]]) { return nil; }
    
    if (raw.count != 9) { return nil; }
    
    // Check that every item is data (and not a nested array)
    for (NSData *item in raw) {
        if (![item isKindOfClass:[NSData class]]) {
            return nil;
        }
    }
    
    Transaction1559 *transaction = [Transaction1559 transaction];
    
    {
        BigNumber *nonce = [BigNumber bigNumberWithData:[raw objectAtIndex:0]];
        if (!nonce.isSafeUnsignedIntegerValue) {
            NSLog(@"WARNING: Nonce is out of range (%@)", nonce);
        }
        transaction.nonce = [nonce unsignedIntegerValue];
    }
    
    {
        NSData *maxPriorityFeePerGas = [raw objectAtIndex:1];
        if (maxPriorityFeePerGas.length > 32) {
            return nil;
        } else {
            transaction.maxPriorityFeePerGas = [BigNumber bigNumberWithData:maxPriorityFeePerGas];
        }
    }
    
    {
        NSData *maxFeePerGas = [raw objectAtIndex:2];
        if (maxFeePerGas.length > 32) {
            return nil;
        } else {
            transaction.maxFeePerGas = [BigNumber bigNumberWithData:maxFeePerGas];
        }
    }
    
    
    {
        NSData *gasLimit = [raw objectAtIndex:3];
        if (gasLimit.length > 32) {
            return nil;
        } else {
            transaction.gasLimit = [BigNumber bigNumberWithData:gasLimit];
        }
    }
    
    {
        NSData *toAddress = [raw objectAtIndex:4];
        if (toAddress.length) {
            transaction.toAddress = [Address addressWithData:toAddress];
            if (!transaction.toAddress) { return nil; }
        }
    }
    
    {
        NSData *value = [raw objectAtIndex:5];
        if (value.length > 32) {
            return nil;
        } else {
            transaction.value = [BigNumber bigNumberWithData:value];
        }
    }
    
    transaction.data = [raw objectAtIndex:6];
    
    {
        NSData *vObject = [raw objectAtIndex:7];
        if (vObject.length > 1) { return nil; }
        
        int v = 0;
        if (vObject.length == 1) {
            [vObject getBytes:&v range:NSMakeRange(0, 1)];
        }
        
        NSData *r = [raw objectAtIndex:8], *s = [raw objectAtIndex:9];;
        if (r.length > 32 || s.length > 32) { return nil; }
        
        NSMutableData *data = [NSMutableData dataWithLength:64];
        memset(data.mutableBytes, 0, 64);
        
        if (r.length) {
            [r getBytes:&data.mutableBytes[32 - r.length] range:NSMakeRange(0, r.length)];
        }
        
        if (s.length) {
            [s getBytes:&data.mutableBytes[64 - s.length] range:NSMakeRange(0, s.length)];
        }
        
        [transaction verifySignatureData:data v:v];
    }
    
    
    return transaction;
}


#pragma mark - Getters (prevent nil)

- (BigNumber*)gasLimit {
    if (!_gasLimit) { return [BigNumber constantZero]; }
    return _gasLimit;
}

- (BigNumber*)maxFeePerGas {
    if (!_maxFeePerGas) { return [BigNumber constantZero]; }
    return _maxFeePerGas;
}

- (BigNumber*)maxPriorityFeePerGas {
    if (!_maxPriorityFeePerGas) { return [BigNumber constantZero]; }
    return _maxPriorityFeePerGas;
}


- (BigNumber*)value {
    if (!_value) { return [BigNumber constantZero]; }
    return _value;
}

- (NSData*)data {
    if (!_data) { return NullData; }
    return _data;
}


#pragma mark - Signature

- (void)_setSignature: (Signature*)signature {
    _signature = signature;
}

- (void)sign:(Account *)account {
    if (account) {
        NSMutableArray *raw = [self _packBasic];
        
        SecureData *result = [SecureData secureData];
        [result appendByte:0x02];
        [result appendData:[RLPSerialization dataWithObject:raw error:nil]];
        
        NSError *error = nil;
        NSData *digest = [SecureData KECCAK256:result.data];
        NSLog(@"digest hexstring === %@",[SecureData secureDataWithData:digest].hexString);
        _fromAddress = account.address;
        _signature = [account signDigest:digest];
        
    } else {
        _fromAddress = nil;
        _signature = nil;
    }
}

- (void)verifySignatureData: (NSData*)signatureData v: (int)v {
    _signature = [Signature signatureWithData:signatureData v:v];
    
    // Use an int so we can detect underflow
    
    NSMutableArray *raw = [self _packBasic];
    [raw addObject:dataWithByte(v)];
    [raw addObject:NullData];
    [raw addObject:NullData];
    
    
    NSData *digest = [SecureData KECCAK256:[RLPSerialization dataWithObject:raw error:nil]];
    
    SecureData *publicKey = [SecureData secureDataWithLength:65];
    
    
    int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, signatureData.bytes, digest.bytes, 0);
    if (!failed) {
        _fromAddress = [Address addressWithData:[[[publicKey subdataFromIndex:1] KECCAK256] subdataFromIndex:12].data];
    }
}


#pragma mark - Serialization

- (NSMutableArray*)_packBasic {
    
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:9];
    
    NSData *chainidData = stripDataZeros(convertIntegerToData(self.chainId));
    if (chainidData.length > 32) { return nil; }
    [result addObject:chainidData];
    
    NSData *nonceData = stripDataZeros(convertIntegerToData(self.nonce));
    if (nonceData.length > 32) { return nil; }
    [result addObject:nonceData];

    if (self.maxPriorityFeePerGas) {
        NSData *valueData2 = stripDataZeros([SecureData hexStringToData:[self.maxPriorityFeePerGas hexString]]);
        if (valueData2.length > 32) { return nil; }
        [result addObject:valueData2];
    } else {
        [result addObject:NullData];
    }
    
    if (self.maxFeePerGas) {
        NSData *valueData3 = stripDataZeros([SecureData hexStringToData:[self.maxFeePerGas hexString]]);
        if (valueData3.length > 32) { return nil; }
        [result addObject:valueData3];
    } else {
        [result addObject:NullData];
    }
    
    if (self.gasLimit) {
        NSData *gasLimitData = stripDataZeros([SecureData hexStringToData:[self.gasLimit hexString]]);
        if (gasLimitData.length > 32) { return nil; }
        [result addObject:gasLimitData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.toAddress) {
        [result addObject:self.toAddress.data];
    } else {
        [result addObject:NullData];
    }
    
    if (self.value) {
        
        NSData *valueData1 = stripDataZeros([SecureData hexStringToData:[self.value hexString]]);
        if (valueData1.length > 32) { return nil; }
        [result addObject:valueData1];
    } else {
        [result addObject:NullData];
    }
    
    if (self.data) {
        [result addObject:self.data];
    } else {
        [result addObject:NullData];
    }
    
    [result addObject:[NSArray array]];
    
    
    // [result addObject:[SecureData secureDataWithHexString:@"c0"]];
    
    return result;
}

- (NSData*)serialize {
    NSMutableArray *raw = [self _packBasic];
    
    if (_signature) {

        [raw addObject:stripDataZeros(dataWithByte(self.signature.v))];
        [raw addObject:stripDataZeros(self.signature.r)];
        [raw addObject:stripDataZeros(self.signature.s)];
        
    } else {
        [raw addObject:NullData];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    SecureData *result = [SecureData secureData];
    [result appendByte:0x02];
    [result appendData:[RLPSerialization dataWithObject:raw error:nil]];
    return result.data;
    
}


- (NSData*)unsignedSerialize {
    NSMutableArray *raw = [self _packBasic];
    
    //    if (_chainId) {
    //        [raw addObject:dataWithByte(_chainId)];
    //        [raw addObject:NullData];
    //        [raw addObject:NullData];
    //    }
    
    SecureData *result = [SecureData secureData];
    [result appendByte:0x02];
    [result appendData:[RLPSerialization dataWithObject:raw error:nil]];
    return result.data;
    
}

- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s {
    NSMutableData *publicKey = [NSMutableData dataWithLength:65];
    
    NSMutableData *sig = [r mutableCopy];
    [sig appendData:s];
    
    NSData *digest = [SecureData KECCAK256:[self unsignedSerialize]];
    
    for (uint8_t recid = 0; recid <= 3; recid++) {
        int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, sig.bytes, digest.bytes, recid);
        if (!failed) {
            _signature = [Signature signatureWithData:[NSData dataWithData:sig] v:recid];
            return;
        }
    }
}

- (Hash*)transactionHash {
    if (!_signature) { return nil; }
    
    
    SecureData *temp = [SecureData secureData];
    [temp appendData:[SecureData KECCAK256:[self serialize]]];
    
    
    return [Hash hashWithData:[SecureData KECCAK256:temp.data]];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    Transaction1559 *transaction = [Transaction1559 transactionWithFromAddress:self.fromAddress];
    transaction.nonce = self.nonce;
    transaction.maxPriorityFeePerGas = [self.maxPriorityFeePerGas copy];
    transaction.maxFeePerGas = [self.maxFeePerGas copy];
    transaction.gasLimit = [self.gasLimit copy];
    transaction.toAddress = self.toAddress;
    transaction.value = [self.value copy];
    transaction.data = [self.data copy];
    transaction.chainId = self.chainId;
    [transaction _setSignature:_signature];
    
    return transaction;
}


#pragma mark - NSObject

- (NSString*)description {
    return [NSString stringWithFormat:@"<Transaction to=%@ from=%@ nonce=%d maxFeePerGas=%@ maxPriorityFeePerGas=%@ gasLimit=%@ value=%@ data=%@ chainId=%d signature=%@>",
            self.toAddress, self.fromAddress, (int)self.nonce, [self.maxFeePerGas decimalString],[self.maxPriorityFeePerGas decimalString], [self.gasLimit decimalString],
            [self.value decimalString], [SecureData dataToHexString:self.data], _chainId, _signature];
}

@end



@implementation HarmonyTransaction

#pragma mark - Life-Cycle

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithFromAddress: (Address*)fromAddress {
    self = [self init];
    if (self) {
        _fromAddress = fromAddress;
    }
    return self;
}

+ (instancetype)transaction {
    return [[HarmonyTransaction alloc] init];
}

+ (instancetype)transactionWithFromAddress:(Address*)fromAddress {
    return [[HarmonyTransaction alloc] initWithFromAddress:fromAddress];
}

+ (instancetype)transactionWithData: (NSData*)transactionData {
    
    // Thinking out loud: Is there ANY difference between a transaction without a gasPrice
    // and one with a gasPrice of zero? If not, we should instantiate BigNumbers for
    // gasPrice, gasLimit, value and NSData for data
    
    // Decode the RLP
    NSError *error = nil;
    NSArray *raw = (NSArray*)[RLPSerialization objectWithData:transactionData error:&error];
    if (error || ![raw isKindOfClass:[NSArray class]]) { return nil; }
    
    if (raw.count != 9) { return nil; }
    
    // Check that every item is data (and not a nested array)
    for (NSData *item in raw) {
        if (![item isKindOfClass:[NSData class]]) {
            return nil;
        }
    }
    
    HarmonyTransaction *transaction = [HarmonyTransaction transaction];
    
    {
        BigNumber *nonce = [BigNumber bigNumberWithData:[raw objectAtIndex:0]];
        if (!nonce.isSafeUnsignedIntegerValue) {
            NSLog(@"WARNING: Nonce is out of range (%@)", nonce);
        }
        transaction.nonce = [nonce unsignedIntegerValue];
    }
    
    {
        NSData *gasPrice = [raw objectAtIndex:1];
        if (gasPrice.length > 32) {
            return nil;
        } else {
            transaction.gasPrice = [BigNumber bigNumberWithData:gasPrice];
        }
    }
    
    {
        NSData *gasLimit = [raw objectAtIndex:2];
        if (gasLimit.length > 32) {
            return nil;
        } else {
            transaction.gasLimit = [BigNumber bigNumberWithData:gasLimit];
        }
    }
    
    {
        NSData *toAddress = [raw objectAtIndex:3];
        if (toAddress.length) {
            transaction.toAddress = [Address addressWithData:toAddress];
            if (!transaction.toAddress) { return nil; }
        }
    }
    
    {
        NSData *value = [raw objectAtIndex:4];
        if (value.length > 32) {
            return nil;
        } else {
            transaction.value = [BigNumber bigNumberWithData:value];
        }
    }
    
    transaction.data = [raw objectAtIndex:5];
    
    {
        NSData *vObject = [raw objectAtIndex:6];
        if (vObject.length > 1) { return nil; }
        
        int v = 0;
        if (vObject.length == 1) {
            [vObject getBytes:&v range:NSMakeRange(0, 1)];
        }
        
        NSData *r = [raw objectAtIndex:7], *s = [raw objectAtIndex:8];;
        if (r.length > 32 || s.length > 32) { return nil; }
        
        NSMutableData *data = [NSMutableData dataWithLength:64];
        memset(data.mutableBytes, 0, 64);
        
        if (r.length) {
            [r getBytes:&data.mutableBytes[32 - r.length] range:NSMakeRange(0, r.length)];
        }
        
        if (s.length) {
            [s getBytes:&data.mutableBytes[64 - s.length] range:NSMakeRange(0, s.length)];
        }
        
        [transaction verifySignatureData:data v:v];
    }
    
    
    return transaction;
}


#pragma mark - Getters (prevent nil)

- (BigNumber*)gasLimit {
    if (!_gasLimit) { return [BigNumber constantZero]; }
    return _gasLimit;
}

- (BigNumber*)gasPrice {
    if (!_gasPrice) { return [BigNumber constantZero]; }
    return _gasPrice;
}

- (BigNumber*)value {
    if (!_value) { return [BigNumber constantZero]; }
    return _value;
}

- (NSData*)data {
    if (!_data) { return NullData; }
    return _data;
}


#pragma mark - Signature

- (void)_setSignature: (Signature*)signature {
    _signature = signature;
}

- (void)sign:(Account *)account {
    if (account) {
        NSMutableArray *raw = [self _packBasic];
        if (_chainId) {
            [raw addObject:dataWithByte(_chainId)];
            [raw addObject:NullData];
            [raw addObject:NullData];
        }
        
        NSError *error = nil;
        NSData *digest = [SecureData KECCAK256:[RLPSerialization dataWithObject:raw error:&error]];
        _fromAddress = account.address;
        _signature = [account signDigest:digest];
        
    } else {
        _fromAddress = nil;
        _signature = nil;
    }
}

- (void)verifySignatureData: (NSData*)signatureData v: (int)v {
    _signature = [Signature signatureWithData:signatureData v:v];
    
    // Use an int so we can detect underflow
    int chainId = (v - 35) / 2;
    if (chainId < 0) { chainId = 0; }
    
    _chainId = chainId;
    
    NSMutableArray *raw = [self _packBasic];
    if (_chainId) {
        [raw addObject:dataWithByte(_chainId)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    NSData *digest = [SecureData KECCAK256:[RLPSerialization dataWithObject:raw error:nil]];
    
    SecureData *publicKey = [SecureData secureDataWithLength:65];
    
    if (_chainId) {
        v -= (_chainId * 2 + 8);
    }
    
    int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, signatureData.bytes, digest.bytes, v - 27);
    if (!failed) {
        _fromAddress = [Address addressWithData:[[[publicKey subdataFromIndex:1] KECCAK256] subdataFromIndex:12].data];
    }
}


#pragma mark - Serialization

- (NSMutableArray*)_packBasic {
    
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:11];
    
    {
        NSData *nonceData = stripDataZeros(convertIntegerToData(self.nonce));
        if (nonceData.length > 32) { return nil; }
        [result addObject:nonceData];
    }
    
    if (self.gasPrice) {
        NSData *gasPriceData = stripDataZeros([SecureData hexStringToData:[self.gasPrice hexString]]);
        if (gasPriceData.length > 32) { return nil; }
        [result addObject:gasPriceData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.gasLimit) {
        NSData *gasLimitData = stripDataZeros([SecureData hexStringToData:[self.gasLimit hexString]]);
        if (gasLimitData.length > 32) { return nil; }
        [result addObject:gasLimitData];
    } else {
        [result addObject:NullData];
    }
    
    
    
    NSData *shardIdData = stripDataZeros(dataWithByte(self.shardId));
    if (shardIdData.length > 32) { return nil; }
    [result addObject:shardIdData];
    
    
    NSData *toShardIdData = stripDataZeros(dataWithByte(self.toShardId));
    if (toShardIdData.length > 32) { return nil; }
    [result addObject:toShardIdData];
    
    
    
    if (self.toAddress) {
        [result addObject:self.toAddress.data];
    } else {
        [result addObject:NullData];
    }
    
    if (self.value) {
        NSData *valueData = stripDataZeros([SecureData hexStringToData:[self.value hexString]]);
        if (valueData.length > 32) { return nil; }
        [result addObject:valueData];
    } else {
        [result addObject:NullData];
    }
    
    if (self.data) {
        [result addObject:self.data];
    } else {
        [result addObject:NullData];
    }
    
    
    
    return result;
}

- (NSData*)serialize {
    NSMutableArray *raw = [self _packBasic];
    
    if (_signature) {
        int v = 27 + self.signature.v;
        if (_chainId) { v += _chainId * 2 + 8; }
        [raw addObject:dataWithByte(v)];
        [raw addObject:stripDataZeros(self.signature.r)];
        [raw addObject:stripDataZeros(self.signature.s)];
        
    } else {
        [raw addObject:dataWithByte(_chainId ? _chainId: 28)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    return [RLPSerialization dataWithObject:raw error:nil];
}

- (NSData*)unsignedSerialize {
    NSMutableArray *raw = [self _packBasic];
    
    if (_chainId) {
        [raw addObject:dataWithByte(_chainId)];
        [raw addObject:NullData];
        [raw addObject:NullData];
    }
    
    return [RLPSerialization dataWithObject:raw error:nil];
}

- (void)populateSignatureWithR: (nonnull NSData*)r s: (nonnull NSData*)s {
    NSMutableData *publicKey = [NSMutableData dataWithLength:65];
    
    NSMutableData *sig = [r mutableCopy];
    [sig appendData:s];
    
    NSData *digest = [SecureData KECCAK256:[self unsignedSerialize]];
    
    for (uint8_t recid = 0; recid <= 3; recid++) {
        int failed = ecdsa_verify_digest_recover(&secp256k1, publicKey.mutableBytes, sig.bytes, digest.bytes, recid);
        if (!failed) {
            _signature = [Signature signatureWithData:[NSData dataWithData:sig] v:recid];
            return;
        }
    }
}

- (Hash*)transactionHash {
    if (!_signature) { return nil; }
    return [Hash hashWithData:[SecureData KECCAK256:[self serialize]]];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    HarmonyTransaction *transaction = [HarmonyTransaction transactionWithFromAddress:self.fromAddress];
    transaction.nonce = self.nonce;
    transaction.shardId = self.shardId;
    transaction.toShardId = self.toShardId;
    transaction.gasPrice = [self.gasPrice copy];
    transaction.gasLimit = [self.gasLimit copy];
    transaction.toAddress = self.toAddress;
    transaction.value = [self.value copy];
    transaction.data = [self.data copy];
    transaction.chainId = self.chainId;
    [transaction _setSignature:_signature];
    
    return transaction;
}


- (Transaction *)convertToEth{
    Transaction *transaction = [Transaction transactionWithFromAddress:self.fromAddress];
    transaction.nonce = self.nonce;
    transaction.gasPrice = [self.gasPrice copy];
    transaction.gasLimit = [self.gasLimit copy];
    transaction.toAddress = self.toAddress;
    transaction.value = [self.value copy];
    transaction.data = [self.data copy];
    transaction.chainId = self.chainId;
    [transaction _setSignature:_signature];
    return transaction;
}


#pragma mark - NSObject

- (NSString*)description {
    return [NSString stringWithFormat:@"<Transaction to=%@ from=%@ nonce=%d gasPrice=%@ gasLimit=%@ value=%@ data=%@ chainId=%d signature=%@>",
            self.toAddress, self.fromAddress, (int)self.nonce, [self.gasPrice decimalString], [self.gasLimit decimalString],
            [self.value decimalString], [SecureData dataToHexString:self.data], _chainId, _signature];
}

@end
