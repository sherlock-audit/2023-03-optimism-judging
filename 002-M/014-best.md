Bauer

medium

# OptimismPortal.depositTransaction continues to function even the protocol paused

## Summary
It is still possible to deposit when the OptimismPortal protocol is paused. This is because OptimismPortal.depositTransaction  lacks the whenNotPaused modifier.

## Vulnerability Detail
It is still possible to deposit when the OptimismPortal protocol is paused. This is because OptimismPortal.depositTransaction  lacks the whenNotPaused modifier.
```solidity
function depositTransaction(
        address _to,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) public payable metered(_gasLimit) {
        // Just to be safe, make sure that people specify address(0) as the target when doing
        // contract creations.
        if (_isCreation) {
            require(
                _to == address(0),
                "OptimismPortal: must send to address(0) when creating a contract"
            );
        }

        // Prevent depositing transactions that have too small of a gas limit.
        require(_gasLimit >= 21_000, "OptimismPortal: gas limit must cover instrinsic gas cost");

        // Transform the from-address to its alias if the caller is a contract.
        address from = msg.sender;
        if (msg.sender != tx.origin) {
            from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
        }

        // Compute the opaque data that will be emitted as part of the TransactionDeposited event.
        // We use opaque data so that we can update the TransactionDeposited event in the future
        // without breaking the current interface.
        bytes memory opaqueData = abi.encodePacked(
            msg.value,
            _value,
            _gasLimit,
            _isCreation,
            _data
        );

        // Emit a TransactionDeposited event so that the rollup node can derive a deposit
        // transaction for this deposit.
        emit TransactionDeposited(from, _to, DEPOSIT_VERSION, opaqueData);
    }

```


## Impact
It is still possible to deposit  even when the OptimismPortal protocol is paused, which is problematic depending on why the protocol is paused



## Code Snippet
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L432

## Tool used

Manual Review

## Recommendation
Add the whenNotPaused modifer to `OptimismPortal.depositTransaction `

