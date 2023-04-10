HE1M

medium

# Missing `onlyEOA` in `OptimismPortal` and `L2ToL1MessagePasser`

## Summary

If contracts directly transfer ETH to `OptimismPortal` or `L2ToL1MessagePasser`, they will lose their fund on the other chain.

## Vulnerability Detail

When ETH is directly transferred to a contract, the function `receive()` will be triggered. 

There are 4 cases that should be considered carefully in Optimism:
 1. [A contract directly transfers ETH to `L1StandardBridge` on L1:](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/L1StandardBridge.sol#L106-L108) In this case, the modifier `onlyEOA` reverts the transaction. This is **correct**, because the receiver on L2 is set to `msg.sender` while the contract on L1 does not have access to that address due to aliasing.
```solidity
receive() external payable override onlyEOA {
        _initiateETHDeposit(msg.sender, msg.sender, RECEIVE_DEFAULT_GAS_LIMIT, bytes(""));
    }
```

 2. [A contract directly transfers ETH to `L2StandardBridge` on L2:](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L2/L2StandardBridge.sol#L74-L83) In this case, the modifier `onlyEOA` reverts the transaction. This is **correct**, because the receiver on L1 is set to `msg.sender` while the contract on L2 does not have access to that address.
```solidity
receive() external payable override onlyEOA {
        _initiateWithdrawal(
            Predeploys.LEGACY_ERC20_ETH,
            msg.sender,
            msg.sender,
            msg.value,
            RECEIVE_DEFAULT_GAS_LIMIT,
            bytes("")
        );
    }
```

 3. [A contract directly transfers ETH to `OptimismPortal` on L1:](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L197-L199) In this case, there is not modifier. This is **not correct**. So, the receiver address on L2 is the address of the contract on L1. So the contract will not have access to the receiver address on L2 due to aliasing.
```solidity
receive() external payable {
        depositTransaction(msg.sender, msg.value, RECEIVE_DEFAULT_GAS_LIMIT, false, bytes(""));
    }
```

 4. [A contract directly transfers ETH to `L2ToL1MessagePasser` on L2:](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L2/L2ToL1MessagePasser.sol#L75-L77) In this case, there is no modifier. This is **not correct**. So, the receiver address on L1 is the address of the contract on L2. So, the contract will not have access to the receiver address on L1.
```solidity
receive() external payable {
        initiateWithdrawal(msg.sender, RECEIVE_DEFAULT_GAS_LIMIT, bytes(""));
    }
```

## Impact

If contracts directly transfer ETH to `OptimismPortal` on L1 or `L2ToL1MessagePasser` on L2, they will lose their fund because they do not have access to the receiver address on the other chain.

## Code Snippet

## Tool used

Manual Review

## Recommendation
It is recommended to use `onlyEOA` for the function `receive()` in both `OptimismPortal` and `L2toL1MessagePasser`.