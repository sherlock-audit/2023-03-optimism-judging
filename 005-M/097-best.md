unforgiven

medium

# valid old withdrawals with more than 25M intrinsic gas can be DOSed by attacker after migration because code cap gasLimit at 25M

## Summary
Function `MigrateWithdrawalGasLimit()` calculates the intrinsic gas cost for the old withdrawals to set it as minGas in their migrated new format. but code cap the calculated gas in 25M while Ethereum current block gas limit is 30M. This can cause some of the withdrawals with big calldata which require 25M-30M gas would be finalized with 25M gas which would result in incomplete execution.

## Vulnerability Detail
This is `MigrateWithdrawalGasLimit()` code:
```go
func MigrateWithdrawalGasLimit(data []byte) uint64 {
	// Compute the cost of the calldata
	dataCost := uint64(0)
	for _, b := range data {
		if b == 0 {
			dataCost += params.TxDataZeroGas
		} else {
			dataCost += params.TxDataNonZeroGasEIP2028
		}
	}

	// Set the outer gas limit. This cannot be zero
	gasLimit := dataCost + 200_000
	// Cap the gas limit to be 25 million to prevent creating withdrawals
	// that go over the block gas limit.
	if gasLimit > 25_000_000 {
		gasLimit = 25_000_000
	}

	return gasLimit
}
```
As you can see code set 25M gas if the calculated gasLimit is bigger than 25M. if there was on old withdrawal which required 25.1M gas (has large calldata) then attack can finalize that withdrawal with 25M gas which the withdrawal execution would revert and the portal won't allow that withdrawal to be finalized again with proper gas.
imagine this scenario:
1. there is an old withdrawal message with big calldata which result in 25.1M required gas.
2. code would migrate this withdrawal with 25M minGas.
3. attacker would finalize this withdrawal with 25.05M gas which would result the `callWithMinGas()` to be passed but revert and the status of the withdrawal would be `finalizedWithdrawals[withdrawalHash] = true` while attacker caused the withdrawal to revert and not executed properly.
4. while before the migration the withdrawal could be correctly finalized after the migration attacker can finalize withdrawal with less gas and cause it to revert.

## Impact
attacker can perform DOS for withdrawal messages that require gas between 25M to 30M.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L114-L116

## Tool used
Manual Review

## Recommendation
cap the gasLimit to 30M