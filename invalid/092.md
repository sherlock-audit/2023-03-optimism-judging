Jeiwan

medium

# `CrossDomainMessenger` over-estimates the gas required to pass cross-chain messages and contradicts the intrinsic gas calculation, forcing users to pay more

## Summary
The gas usage of cross-chain messages sent via `CrossDomainMessenger.sendMessage` is over-estimated: each 0 byte of data is estimated as 16 gas units, but, according to the Ethereum Yellow Paper, a zero byte of data costs 4 gas units.
## Vulnerability Detail
The [CrossDomainMessenger.sendMessage](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L247) function is used to send cross-chain messages. The function [computes](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258) the amount of gas required to pass the message to the other chain: this is done in the [baseGas](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258) function, which [computes the byte-wise cost of the message](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L432). The gas consumption of a message is made of three components:
1. the [dynamic overhead](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L429-L430);
1. the [calldata overhead](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L432);
1. and the [constant minimal overhead](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L434).

The calldata overhead of a message is the amount of gas required to pass the message in a transaction. As per the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) (see Appendix G. Fee Schedule), passing a zero byte costs 4 gas, while passing a non-zero byte costs 16 gas. However, the `baseGas` function sets 16 gas per byte no matter whether the byte is zero or not.

This contradicts the [intrinsic gas calculation in `op-geth`](https://github.com/ethereum-optimism/op-geth/blob/optimism/core/state_transition.go#L86-L99), which applies different gas cost to zero and non-zero bytes:
```go
nonZeroGas := params.TxDataNonZeroGasFrontier
if isEIP2028 {
    nonZeroGas = params.TxDataNonZeroGasEIP2028
}
if (math.MaxUint64-gas)/nonZeroGas < nz {
    return 0, ErrGasUintOverflow
}
gas += nz * nonZeroGas

z := dataLen - nz
if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
    return 0, ErrGasUintOverflow
}
gas += z * params.TxDataZeroGas
```

Thus, the gas limit paid for by users will always be bigger than the intrinsic gas of messages.

This behaviour also disagrees with how the migration process works: when computing the gas cost of legacy withdrawals, [the gas cost of zero and non-zero bytes is counted correctly](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L101-L108).

## Impact
Taking into account that ABI encoding produces sparse data (many data types are left-padded with zero bytes), the effect of the over-estimation will be significant and will affect many users. Consider two most popular data types in Solidity:
1. The `address` type, when ABI-encoded, is always left-padded with 12 zero bytes: out of 32 bytes of an encoded address, 12 bytes will always be zero bytes. Thus, zero bytes will make 37.5% of every address.
1. The `uint256` type, when ABI-encoded, is left-padded with zero bytes to make the encoded length of the encoded data 32 bytes. The most common use case of the type is currency amounts, which mostly use 18 decimals. Most amounts don't take the entire 32 bytes; let's assume that 12 bytes (this is ~79,228,162,514.26434e18) will be enough for the majority of amounts that are used in protocols. Thus, zero bytes will make at least 62.5% of every `uint256` value.

To sum it up: 37.5% of bytes required to pass addresses and at least 62.5% of bytes required to pass `uint256` values will cost *4 times* more than expected. This is a significant increase of gas cost for users.

To get more practical numbers, we can check what messages the bridge contracts (the main contracts to transfer funds between L1 and L2) will pass:
1. To [bridge ETH](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L377-L387), the following calldata is passed: 4 bytes of the `finalizeBridgeETH` function selector, "from" and "to" addresses, a `uint256` amount of ETH to bridge, and arbitrary extra bytes. The signature (`0x1635f5fd`) has no zero bytes. The two addresses have 24 zero bytes. The value has 20 zero-bytes (as per our assumption above). The arbitrary can have any number of bytes. Thus, out of 76 bytes (4 + 20 + 20 + 32), 44, or ~57.8%, will be zero and will cost 4 times more gas than they should. This is a ~77% increase in gas cost ($(76 * 16) / ((44 * 4) + ((76 - 44) * 16)) = 1.7674418604651163$).
1. To [bridge ERC20](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L427-L442), the following calldata will be passed: 4 bytes of the `finalizeBridgeERC20` function selector, remote and local token addresses, "from" and "to" addresses, a `uint256` amount of tokens to bridge, and arbitrary extra bytes. Out of 116 bytes (4 + 20 + 20 + 20 + 20 + 32), 68, or ~58.6% will be zero and will cost 4 times more gas than they should. This is a ~78% increase in gas cost ($(116 * 16) / ((68 * 4) + ((116 - 68) * 16)) = 1.7846153846153847$).

The two bridge contracts ([L1StandardBridge](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/L1StandardBridge.sol#L20) and [L2StandardBridge](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L2/L2StandardBridge.sol#L20), that inherit from [StandardBridge](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L20)) are the main contracts on Optimism Bedrock to bridge ETH and ERC20. Thus, Optimism users will pay ~177% for the gas required to bridge tokens.

Another important moment here is how this gas is paid. When sending messages from L1 to L2, `OptimismPortal` [meters](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L432) the gas limit of each message. The metering [implements](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L92) an EIP-1559-like mechanism to set gas price based on the demand for gas. Due to the over-estimation of gas in `CrossDomainMessenger`, the mechanism will detect *higher* gas demand and will increase gas price *faster* than expected. In other words, the over-estimation will both increase gas limit and gas price–users will pay more for more gas.
## Code Snippet
1. `CrossDomainMessenger.sendMessage` sends cross-chain messages:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L247
1. `baseGas` computes the amount of gas required to send a message:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258
1. `baseGas` assigns the price of 16 bytes to both zero and non-zero bytes:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L432
## Tool used
Manual Review
## Recommendation
In the `CrossDomainMessenger.baseGas`, consider assigning 4 gas to zero bytes and 16 gas to non-zero bytes, as per the Ethereum Yellow Paper. This is also how the [cost of cross-chain messages is computed during the migration](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L101-L108).