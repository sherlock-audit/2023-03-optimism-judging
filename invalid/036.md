0xChinedu

medium

# No Transfer of Ownership Pattern

## Summary
 The owner may accidentally transfer ownership to an uncontrolled account, breaking all functions with the onlyOwner() modifier.
## Vulnerability Detail
The current ownership transfer process involves the current owner calling CrossDomainOwnable3.transferOwnership(). This function checks the new owner is not the zero address and proceeds to write the new owner's address into the owner's state variable. If the nominated EOA account is not a valid account, it is entirely possible the owner may accidentally transfer ownership to an uncontrolled account, breaking all functions with the onlyOwner() modifier.
## Impact
As a result, all the onlyOwner functions will be inaccessible by contracts on either L1 or L2.
## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L2/CrossDomainOwnable3.sol#L37
```solidity
    function transferOwnership(address _owner, bool _isLocal) external onlyOwner {
        require(_owner != address(0), "CrossDomainOwnable3: new owner is the zero address");

        address oldOwner = owner();
        _transferOwnership(_owner);
        isLocal = _isLocal;

        emit OwnershipTransferred(oldOwner, _owner, _isLocal);
    }
```
## Tool used

Manual Review

## Recommendation
Consider implementing a two step process where the owner nominates an account and the nominated account needs to call an acceptOwnership() function for the transfer of ownership to fully succeed. This ensures the nominated EOA account is a valid and active account.