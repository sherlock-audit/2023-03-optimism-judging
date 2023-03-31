HE1M

medium

# Incorrect calculation of required gas limit during deposit transaction

## Summary

It is possible to bypass burning the gas on L1 if `_gasLimit` is accurately chosen between 21000 and used gas.

## Vulnerability Detail

The gas that deposit transactions use on L2 is bought on L1 via a gas burn in `ResourceMeterin.sol`:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L432
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L162

There is also a condition on the parameter `_gasLimit` to protect against DoS attack:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L443

But, by using this limitation, it does not enforce to burn correct amount of gas on L1. Because, if the following condition is satisfied, the user will not burn any gas for the transaction on L2 (it only pays gas for the L1 transaction):

`21000 <= _gasLimit <= [usedGas * max(block.basefee, 1 gwei) / prevBaseFee]`

The condition `21000 <= _gasLimit` will satisfy the condtion:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L443

The condition `_gasLimit <= [usedGas * max(block.basefee, 1 gwei) / prevBaseFee]` will bypass the condition (so no gas will be burned on L1):
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L161-L163

For instance, if a user provides a long bytes as `_data` parameter, the `usedGas` will be increased, so the margin between 21000 to `[usedGas * max(block.basefee, 1 gwei) / prevBaseFee]` will be increased as well. By choosing a `_gasLimit` in this range, the burning gas mechanism can be bypassed. If the `_gasLimit` is set to the minimum allowed value (21000), this transaction will be failed most probably on L2 due to not enough gas limit. All in all, the sequencer would not be compensated although he processed a long data.

## Impact
 - Using L2 resources without enough compensation.
 - DoS 
## Code Snippet

## Tool used

Manual Review

## Recommendation

It is recommended to include the `_data` length as well as 21000 to the lower bound of gas limit:
```solidity
require(_gasLimit >= 21_000 + _data.length * 16, "OptimismPortal: gas limit must cover instrinsic gas cost");
```