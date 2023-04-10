Jeiwan

high

# Legacy withdrawals can be relayed twice, causing double spending of bridged assets

## Summary
`L2CrossDomainMessenger.relayMessage` checks that legacy messages have not been relayed by reading from the `successfulMessages` state variable, however the contract's storage will wiped during the migration to Bedrock and `successfulMessages` will be empty after the deployment of the contract. The check will always pass, even if a legacy message have already been relayed using its v0 hash. As a result, random withdrawal messages, as well as messages from malicious actors, can be relayed multiple times during the migration: first, as legacy v0 messages (before the migration); then, as Bedrock v1 messages (during the migration).
## Vulnerability Detail
[L2CrossDomainMessenger](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L2/L2CrossDomainMessenger.sol#L18) inherits from [CrossDomainMessenger](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L114), which inherits from `CrossDomainMessengerLegacySpacer0`, `CrossDomainMessengerLegacySpacer1`, assuming that the contract will be deployed at an address with existing state–the two spacer contracts are needed to "skip" the slots occupied by previous implementations of the contract.

During the migration, legacy (i.e. pre-Bedrock) withdrawal messages will be [converted](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L55) to Bedrock messages–they're [expected to call the `relayMessage` function](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L74-L80) of `L2CrossDomainMessenger`. The `L2CrossDomainMessenger.relayMessage` function [checks that the relayed legacy message haven't been relayed already](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L305-L313):
```solidity
// If the message is version 0, then it's a migrated legacy withdrawal. We therefore need
// to check that the legacy version of the message has not already been relayed.
if (version == 0) {
    bytes32 oldHash = Hashing.hashCrossDomainMessageV0(_target, _sender, _message, _nonce);
    require(
        successfulMessages[oldHash] == false,
        "CrossDomainMessenger: legacy withdrawal already relayed"
    );
}
```

It reads a V0 message hash from the `successfulMessages` state variable, assuming that the content of the variable is preserved during the migration. However, the [state and storage of all predeployed contracts is wiped during the migration](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/genesis/db_migration.go#L150-L157):
```go
// We need to wipe the storage of every predeployed contract EXCEPT for the GovernanceToken,
// WETH9, the DeployerWhitelist, the LegacyMessagePasser, and LegacyERC20ETH. We have verified
// that none of the legacy storage (other than the aforementioned contracts) is accessible and
// therefore can be safely removed from the database. Storage must be wiped before anything
// else or the ERC-1967 proxy storage slots will be removed.
if err := WipePredeployStorage(db); err != nil {
    return nil, fmt.Errorf("cannot wipe storage: %w", err)
}
```

Also notice that [withdrawals are migrated *after* predeploys were wiped and deployed](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/genesis/db_migration.go#L150-L192)–predeploys will have empty storage at the time withdrawals are migrated.

Moreover, if we check the [code at the `L2CrossDomainMessenger` address](https://optimistic.etherscan.io/address/0x4200000000000000000000000000000000000007#code) of the current version of Optimism, we'll see that the contract's storage layout is different from the layout of the `CrossDomainMessengerLegacySpacer0` and `CrossDomainMessengerLegacySpacer1` contracts: there are no gaps and other spacer slots; `successfulMessages` is the second slot of the contract. Thus, even if there were no wiping, the `successfulMessages` mapping of the new `L2CrossDomainMessenger` contract would still be empty.
## Impact
Withdrawal messages can be relayed twice: once right before and once during the migration. ETH and ERC20 tokens can be withdrawn twice, which is basically double spending of bridged assets.
## Code Snippet
1. `L2CrossDomainMessenger` is `CrossDomainMessenger`:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L2/L2CrossDomainMessenger.sol#L18
1. `CrossDomainMessenger` inherits from `CrossDomainMessengerLegacySpacer0` and `CrossDomainMessengerLegacySpacer1` to preserve the storage layout:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L114-L117
1. `CrossDomainMessenger.relayMessage` reads from `successfulMessages` to ensure that legacy withdrawals haven't been relayed already:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L307-L313
1. All predeploys are wiped during the migration, thus `L2CrossDomainMessenger.successfulMessages` will not contain the hashes of legacy withdrawals:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/genesis/db_migration.go#L150-L157
## Tool used
Manual Review
## Recommendation
1. Consider cleaning up the storage layout of `L1CrossDomainMessenger`, `L2CrossDomainMessenger` and other proxied contracts.
1. In the [PreCheckWithdrawals](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/precheck.go#L21) function, consider reading withdrawal hashes from the `successfulMessages` mapping of the old `L2CrossDomainMessenger` contract and checking if the values are set. Successful withdrawals should be skipped at this point to filter out legacy withdrawals that have already been relayed.
1. Consider removing the [check](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L307-L313) from the `relayMessage` function, since the check will be useless due to the empty state of the contract.