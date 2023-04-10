Koolex

medium

# Possible loss of funds in case extra ether sent to **OptimismPortal** for old withdrawals

## Summary
Possible loss of funds in case extra ether sent to **OptimismPortal** for old withdrawals

## Vulnerability Detail
Optimism added `donateETH` method in **OptimismPortal** contract.
As per the comment it exists for the sake of the migration
> This function mainly exists for the sake of the migration between the legacy Optimism system and Bedrock.

This makes sense since **OptimismPortal** will initially have zero ether. Old withdrawals (i.e. from legacy Optimism system) that has value bigger than zero can not be finalized if there is no funds in **OptimismPortal** contract. That's why `donateETH` method exists. Optimism team should send the exact sum of all ether of old withdrawals. Since a miscalculation of exact needed ether of old and only non-relayed withdrawals is likely, if any extra ether sent, it gets stuck in **OptimismPortal** contract as there is no way to rescue stuck ether from it.

## Impact
Loss of funds in case extra ether sent to **OptimismPortal** for old withdrawals

## Code Snippet


```sh
/**
 * @notice Accepts ETH value without triggering a deposit to L2. This function mainly exists
 *         for the sake of the migration between the legacy Optimism system and Bedrock.
 */
function donateETH() external payable {
	// Intentionally empty.
}
```

https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L205

## Tool used

Manual Review

## Recommendation

 Add a method to recover only donated ether from **OptimismPortal**.
 
  