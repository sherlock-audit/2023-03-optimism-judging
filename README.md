# Issue H-1: All migrated withdrarwals that require more than 135,175 gas may be bricked 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/93 

## Found by 
obront

## Summary

Migrated withdrawals are given an "outer" (Portal) gas limit of `calldata cost + 200,000`, and an "inner" (CrossDomainMessenger) gas limit of `0`. The assumption is that the CrossDomainMessenger is replayable, so there is no need to specify a correct gas limit.

This is an incorect assumption. For any withdrawals that require more than 135,175 gas, insufficient gas can be sent such that CrossDomainMessenger's external call reverts and the remaining 1/64th of the gas sent is not enough for replayability to be encoded in the Cross Domain Messenger.

However, the remaining 1/64th of gas in the Portal is sufficient to have the transaction finalize, so that the Portal will not process the withdrawal again.

## Vulnerability Detail

When old withdrawals are migrated to Bedrock, they are encoded as calls to `L1CrossDomainMessenger.relayMessage()` as follows:

```go
func MigrateWithdrawal(withdrawal *LegacyWithdrawal, l1CrossDomainMessenger *common.Address) (*Withdrawal, error) {
	// Attempt to parse the value
	value, err := withdrawal.Value()
	if err != nil {
		return nil, fmt.Errorf("cannot migrate withdrawal: %w", err)
	}

	abi, err := bindings.L1CrossDomainMessengerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}

	// Migrated withdrawals are specified as version 0. Both the
	// L2ToL1MessagePasser and the CrossDomainMessenger use the same
	// versioning scheme. Both should be set to version 0
	versionedNonce := EncodeVersionedNonce(withdrawal.XDomainNonce, new(big.Int))
	// Encode the call to `relayMessage` on the `CrossDomainMessenger`.
	// The minGasLimit can safely be 0 here.
	data, err := abi.Pack(
		"relayMessage",
		versionedNonce,
		withdrawal.XDomainSender,
		withdrawal.XDomainTarget,
		value,
		new(big.Int), // <= THIS IS THE INNER GAS LIMIT BEING SET TO ZERO
		[]byte(withdrawal.XDomainData),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot abi encode relayMessage: %w", err)
	}

	gasLimit := MigrateWithdrawalGasLimit(data)

	w := NewWithdrawal(
		versionedNonce,
		&predeploys.L2CrossDomainMessengerAddr,
		l1CrossDomainMessenger,
		value,
		new(big.Int).SetUint64(gasLimit), // <= THIS IS THE OUTER GAS LIMIT BEING SET
		data,
	)
	return w, nil
}
```

As we can see, the `relayMessage()` call uses a gasLimit of zero (see comments above), while the outer gas limit is calculated by the `MigrateWithdrawalGasLimit()` function:

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
This calculates the outer gas limit value by adding the calldata cost to 200,000.

Let's move over to the scenario in which these values are used to see why they can cause a problem.

When a transaction is proven, we can call `OptimismPortal.finalizeWithdrawalTransaction()` to execute the transaction. In the case of migrated withdrawals, this executes the following flow:
- `OptimismPortal` calls to `L1CrossDomainMessenger` with a gas limit of `200,000 + calldata`
- This guarantees remaining gas for continued execution after the call of `(200_000 + calldata) * 64/63 * 1/64 > 3174`
- XDM uses `41,002` gas before making the call, leaving `158,998` remaining for the call
- The `SafeCall.callWithMinGas()` succeeds, since the inner gas limit is set to 0
- If the call uses up all of the avaialble gas (succeeding or reverting), we are left with `158,998 * 1/64 = 2,484` for the remaining execution
- The remaining execution includes multiple SSTOREs which totals `23,823` gas, resulting in an OutOfGas revert
- In fact, if the call uses any amount greater than `135,175`, we will have less than `23,823` gas remaining and will revert
- As a result, none of the updates to `L1CrossDomainMessenger` occur, and the transaction is not marked in `failedMessages` for replayability
- However, the remaining `3174` gas is sufficient to complete the transction on the `OptimismPortal`, which sets `finalizedWithdrawals[hash] = true` and locks the withdrawals from ever being made again

## Impact

Any migrated withdrawal that uses more than `135,175` gas will be bricked if insufficient gas is sent. This could be done by a malicious attacker bricking thousands of pending withdrawals or, more likely, could happen to users who accidentally executed their withdrawal with too little gas and ended up losing it permanently.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L55-L97

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L99-L119

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L315-L412

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L291-L383

## Tool used

Manual Review

## Recommendation

There doesn't seem to be an easy fix for this, except to adjust the migration process so that migrated withdrawals are directly saved as `failedMessages` on the `L1CrossDomainMessenger` (and marked as `finalizedWithdrawals` on the `OptimismPortal`), rather than needing to be reproven through the normal flow.



## Discussion

**maurelian**

Valid but we believe it to be a medium. There definitely exist edge cases of transactions where this is an issue but the majority of transactions it is not an issue.

Based on the following call trace for a finalization of a withdrawal transaction + the address mapping, we believe that this issue is unable to impact transactions transferring ERC20 tokens through the bridge. 

```
{
  "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
  "gas": "0x73bdc",
  "gasUsed": "0x3ebbe",
  "to": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
  "input": "0x8c3152e9000000000000000000000000000000000000000000000000000000000000002000010000000000000000000000000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000007000000000000000000000000dc64a140aa3e981100a9beca4e685f962f0cf6c900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000031b8000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001e4d764ad0b000100000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000100000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e40166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "calls": [
    {
      "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
      "gas": "0x70b60",
      "gasUsed": "0x3fb97",
      "to": "0x0dcd1bf9a1b36ce34237eeafef220932846bcd82",
      "input": "0x8c3152e9000000000000000000000000000000000000000000000000000000000000002000010000000000000000000000000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000007000000000000000000000000dc64a140aa3e981100a9beca4e685f962f0cf6c900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000031b8000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001e4d764ad0b000100000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000100000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e40166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "calls": [
        {
          "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
          "gas": "0x6b7b4",
          "gasUsed": "0x1c91",
          "to": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
          "input": "0x88786272",
          "output": "0x0000000000000000000000000000000000000000000000000000000064370353",
          "calls": [
            {
              "from": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
              "gas": "0x689d2",
              "gasUsed": "0x91a",
              "to": "0xa51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0",
              "input": "0x88786272",
              "output": "0x0000000000000000000000000000000000000000000000000000000064370353",
              "value": "0x0",
              "type": "DELEGATECALL"
            }
          ],
          "type": "STATICCALL"
        },
        {
          "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
          "gas": "0x69a01",
          "gasUsed": "0x2f3",
          "to": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
          "input": "0xf4daa291",
          "output": "0x0000000000000000000000000000000000000000000000000000000000000002",
          "calls": [
            {
              "from": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
              "gas": "0x67de3",
              "gasUsed": "0x110",
              "to": "0xa51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0",
              "input": "0xf4daa291",
              "output": "0x0000000000000000000000000000000000000000000000000000000000000002",
              "value": "0x0",
              "type": "DELEGATECALL"
            }
          ],
          "type": "STATICCALL"
        },
        {
          "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
          "gas": "0x6953a",
          "gasUsed": "0x1d86",
          "to": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
          "input": "0xa25ae557000000000000000000000000000000000000000000000000000000000000000b",
          "output": "0x3cef4cf4a4886782e55500db2d25325cb17007808ba2d44e0e37e7194f485da2000000000000000000000000000000000000000000000000000000006437057000000000000000000000000000000000000000000000000000000000000000f0",
          "calls": [
            {
              "from": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
              "gas": "0x6792d",
              "gasUsed": "0x1b9a",
              "to": "0xa51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0",
              "input": "0xa25ae557000000000000000000000000000000000000000000000000000000000000000b",
              "output": "0x3cef4cf4a4886782e55500db2d25325cb17007808ba2d44e0e37e7194f485da2000000000000000000000000000000000000000000000000000000006437057000000000000000000000000000000000000000000000000000000000000000f0",
              "value": "0x0",
              "type": "DELEGATECALL"
            }
          ],
          "type": "STATICCALL"
        },
        {
          "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
          "gas": "0x6759c",
          "gasUsed": "0x2f3",
          "to": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
          "input": "0xf4daa291",
          "output": "0x0000000000000000000000000000000000000000000000000000000000000002",
          "calls": [
            {
              "from": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
              "gas": "0x65a10",
              "gasUsed": "0x110",
              "to": "0xa51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0",
              "input": "0xf4daa291",
              "output": "0x0000000000000000000000000000000000000000000000000000000000000002",
              "value": "0x0",
              "type": "DELEGATECALL"
            }
          ],
          "type": "STATICCALL"
        },
        {
          "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
          "gas": "0x6053e",
          "gasUsed": "0x306f9",
          "to": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
          "input": "0xd764ad0b000100000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000100000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e40166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "calls": [
            {
              "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
              "gas": "0x5d111",
              "gasUsed": "0xc8d",
              "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
              "input": "0xbf40fac10000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4f564d5f4c3143726f7373446f6d61696e4d657373656e676572000000000000",
              "output": "0x000000000000000000000000610178da211fef7d417bc0e6fed39f05609ad788",
              "type": "STATICCALL"
            },
            {
              "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
              "gas": "0x5b909",
              "gasUsed": "0x2d19f",
              "to": "0x610178da211fef7d417bc0e6fed39f05609ad788",
              "input": "0xd764ad0b000100000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000100000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e40166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "calls": [
                {
                  "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
                  "gas": "0x54236",
                  "gasUsed": "0x354",
                  "to": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
                  "input": "0x9bf62d82",
                  "output": "0x0000000000000000000000004200000000000000000000000000000000000007",
                  "calls": [
                    {
                      "from": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
                      "gas": "0x52b78",
                      "gasUsed": "0x171",
                      "to": "0x0dcd1bf9a1b36ce34237eeafef220932846bcd82",
                      "input": "0x9bf62d82",
                      "output": "0x0000000000000000000000004200000000000000000000000000000000000007",
                      "value": "0x0",
                      "type": "DELEGATECALL"
                    }
                  ],
                  "type": "STATICCALL"
                },
                {
                  "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
                  "gas": "0x50df0",
                  "gasUsed": "0x1e56d",
                  "to": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                  "input": "0x0166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000",
                  "calls": [
                    {
                      "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                      "gas": "0x4e57f",
                      "gasUsed": "0x92b",
                      "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                      "input": "0xb7947262",
                      "output": "0x0000000000000000000000000000000000000000000000000000000000000000",
                      "type": "STATICCALL"
                    },
                    {
                      "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                      "gas": "0x4c8cb",
                      "gasUsed": "0x1b395", // <--- HERE
                      "to": "0xb7f8bc63bbcad18155201308c8f3540b07f84f5e",
                      "input": "0x0166a07a000000000000000000000000e6e340d132b5f46d1e472debcd681b2abc16e57e0000000000000000000000007c6b91d9be155a6db01f749217d76ff02a7227f2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000",
                      "calls": [
                        {
                          "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                          "gas": "0x4b1b5",
                          "gasUsed": "0xc75",
                          "to": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
                          "input": "0x6e296e45",
                          "output": "0x0000000000000000000000004200000000000000000000000000000000000010",
                          "calls": [
                            {
                              "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
                              "gas": "0x49bd4",
                              "gasUsed": "0x4bd",
                              "to": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
                              "input": "0xbf40fac10000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4f564d5f4c3143726f7373446f6d61696e4d657373656e676572000000000000",
                              "output": "0x000000000000000000000000610178da211fef7d417bc0e6fed39f05609ad788",
                              "type": "STATICCALL"
                            },
                            {
                              "from": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
                              "gas": "0x49570",
                              "gasUsed": "0x224",
                              "to": "0x610178da211fef7d417bc0e6fed39f05609ad788",
                              "input": "0x6e296e45",
                              "output": "0x0000000000000000000000004200000000000000000000000000000000000010",
                              "value": "0x0",
                              "type": "DELEGATECALL"
                            }
                          ],
                          "type": "STATICCALL"
                        },
                        {
                          "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                          "gas": "0x7530",
                          "gasUsed": "0x7530",
                          "to": "0xe6e340d132b5f46d1e472debcd681b2abc16e57e",
                          "input": "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000",
                          "error": "write protection",
                          "type": "STATICCALL"
                        },
                        {
                          "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                          "gas": "0x7530",
                          "gasUsed": "0x7530",
                          "to": "0xe6e340d132b5f46d1e472debcd681b2abc16e57e",
                          "input": "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000",
                          "error": "write protection",
                          "type": "STATICCALL"
                        },
                        {
                          "from": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
                          "gas": "0x39714",
                          "gasUsed": "0x7405",
                          "to": "0xe6e340d132b5f46d1e472debcd681b2abc16e57e",
                          "input": "0xa9059cbb000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000de0b6b3a7640000",
                          "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
                          "value": "0x0",
                          "type": "CALL"
                        }
                      ],
                      "value": "0x0",
                      "type": "DELEGATECALL"
                    }
                  ],
                  "value": "0x0",
                  "type": "CALL"
                }
              ],
              "value": "0x0",
              "type": "DELEGATECALL"
            }
          ],
          "value": "0x0",
          "type": "CALL"
        }
      ],
      "value": "0x0",
      "type": "DELEGATECALL"
    }
  ],
  "value": "0x0",
  "type": "CALL"
}
```

**GalloDaSballo**

Would suggest checking for known withdrawals and seeing if this can be a concern (and raising to High in that case)

The conditionality leads me to agree with Med

**GalloDaSballo**

Sample list of withdrawals
https://gist.github.com/GalloDaSballo/66d73fb9d2f5fdf904349406ceb5ebfb

Annotated Gas Consumption of integrations
https://gist.github.com/GalloDaSballo/9dd42b901528f31fe8db244cfb1ef514
https://gist.github.com/GalloDaSballo/f27d5a6cf7bd0ec7dd03b5de7d3bcdaf

I believe there are some cases in which the above txs, which have corresponding events, will require more than 135k gas meaning they are subject to the attack

**GalloDaSballo**

I think this is a valid example:
https://explorer.phalcon.xyz/tx/eth/0x610d1ca15b934970949f138a6e11847179ada6adff867621d03d220962aa5fc9?line=14

relayMessage -> does something -> send a message back

Contract: https://etherscan.io/address/0xcEA770441aa5eFCD3f5501b796185Ec3055A76D7/advanced#internaltx

**koolexcrypto**

Escalate for 10 USDC.

While the issue is creatively accurate with the specified gas values, it still requires certain conditions to be feasbile (e.g. only withdrarwals require more than 135,175 gas).

According to [Sherlock's Criteria](https://docs.sherlock.xyz/audits/judging/judging#how-to-identify-a-medium-issue), it is a valid medium.
> Causes a loss of funds but requires certain external conditions or specific states

Lastly, all the respect to the good efforts put in behind this finding.


**sherlock-admin**

 > Escalate for 10 USDC.
> 
> While the issue is creatively accurate with the specified gas values, it still requires certain conditions to be feasbile (e.g. only withdrarwals require more than 135,175 gas).
> 
> According to [Sherlock's Criteria](https://docs.sherlock.xyz/audits/judging/judging#how-to-identify-a-medium-issue), it is a valid medium.
> > Causes a loss of funds but requires certain external conditions or specific states
> 
> Lastly, all the respect to the good efforts put in behind this finding.
> 

You've created a valid escalation for 10 USDC!

To remove the escalation from consideration: Delete your comment.

You may delete or edit your escalation comment anytime before the 48-hour escalation window closes. After that, the escalation becomes final.

**hrishibhat**

Escalation rejected

Lead Judge comment:
```
Maintain High Severity because while the condition is necessary it is not up to the user to decide whether that requirement was met but rather the requirement is imposed by the script 
```
This is a valid flaw in the system due to an incorrect assumption. 


**sherlock-admin**

> Escalation rejected
> 
> Lead Judge comment:
> ```
> Maintain High Severity because while the condition is necessary it is not up to the user to decide whether that requirement was met but rather the requirement is imposed by the script 
> ```
> This is a valid flaw in the system due to an incorrect assumption. 
> 

This issue's escalations have been rejected!

Watsons who escalated this issue will have their escalation amount deducted from their next payout.

# Issue H-2: Legacy withdrawals can be relayed twice, causing double spending of bridged assets 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/87 

## Found by 
Jeiwan

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



## Discussion

**hrishibhat**

Sponsor comment:
This report is valid. The storage layout of the new `CrossDomainMessenger` contract is different from the old `CrossDomainMessenger`, which allows for replaying old cross domain messages- this would be catastrophic for the network.

# Issue H-3: The formula used in ````SafeCall.callWithMinGas()```` is wrong 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/40 

## Found by 
KingNFT, ShadowForce

## Summary
The formula used in ````SafeCall.callWithMinGas()```` is not fully complying with EIP-150 and EIP-2929, the actual gas received by the sub-contract can be less than the required ````_minGas````. Withdrawal transactions can be finalized with less than specified gas limit, may lead to loss of funds.

## Vulnerability Detail
```solidity
File: contracts\libraries\SafeCall.sol
048:     function callWithMinGas(
049:         address _target,
050:         uint256 _minGas,
051:         uint256 _value,
052:         bytes memory _calldata
053:     ) internal returns (bool) {
054:         bool _success;
055:         assembly {
056:             // Assertion: gasleft() >= ((_minGas + 200) * 64) / 63
057:             //
058:             // Because EIP-150 ensures that, a maximum of 63/64ths of the remaining gas in the call
059:             // frame may be passed to a subcontext, we need to ensure that the gas will not be
060:             // truncated to hold this function's invariant: "If a call is performed by
061:             // `callWithMinGas`, it must receive at least the specified minimum gas limit." In
062:             // addition, exactly 51 gas is consumed between the below `GAS` opcode and the `CALL`
063:             // opcode, so it is factored in with some extra room for error.
064:             if lt(gas(), div(mul(64, add(_minGas, 200)), 63)) {
065:                 // Store the "Error(string)" selector in scratch space.
066:                 mstore(0, 0x08c379a0)
067:                 // Store the pointer to the string length in scratch space.
068:                 mstore(32, 32)
069:                 // Store the string.
070:                 //
071:                 // SAFETY:
072:                 // - We pad the beginning of the string with two zero bytes as well as the
073:                 // length (24) to ensure that we override the free memory pointer at offset
074:                 // 0x40. This is necessary because the free memory pointer is likely to
075:                 // be greater than 1 byte when this function is called, but it is incredibly
076:                 // unlikely that it will be greater than 3 bytes. As for the data within
077:                 // 0x60, it is ensured that it is 0 due to 0x60 being the zero offset.
078:                 // - It's fine to clobber the free memory pointer, we're reverting.
079:                 mstore(88, 0x0000185361666543616c6c3a204e6f7420656e6f75676820676173)
080: 
081:                 // Revert with 'Error("SafeCall: Not enough gas")'
082:                 revert(28, 100)
083:             }
084: 
085:             // The call will be supplied at least (((_minGas + 200) * 64) / 63) - 49 gas due to the
086:             // above assertion. This ensures that, in all circumstances, the call will
087:             // receive at least the minimum amount of gas specified.
088:             // We can prove this property by solving the inequalities:
089:             // ((((_minGas + 200) * 64) / 63) - 49) >= _minGas
090:             // ((((_minGas + 200) * 64) / 63) - 51) * (63 / 64) >= _minGas
091:             // Both inequalities hold true for all possible values of `_minGas`.
092:             _success := call(
093:                 gas(), // gas
094:                 _target, // recipient
095:                 _value, // ether value
096:                 add(_calldata, 32), // inloc
097:                 mload(_calldata), // inlen
098:                 0x00, // outloc
099:                 0x00 // outlen
100:             )
101:         }
102:         return _success;
103:     }

```
The current formula used in ````SafeCall.callWithMinGas()```` involves two issues.

### Firstly, the ````63/64```` rule is not the whole story of EIP-150 for the ````CALL```` opcode, let's take a look at the implementation of EIP-150, a ````base```` gas is subtracted before applying ````63/64```` rule.
https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/core/vm/gas.go#L37
```go
func callGas(isEip150 bool, availableGas, base uint64, callCost *uint256.Int) (uint64, error) {
	if isEip150 {
		availableGas = availableGas - base
		gas := availableGas - availableGas/64
		// If the bit length exceeds 64 bit we know that the newly calculated "gas" for EIP150
		// is smaller than the requested amount. Therefore we return the new gas instead
		// of returning an error.
		if !callCost.IsUint64() || gas < callCost.Uint64() {
			return gas, nil
		}
	}
	if !callCost.IsUint64() {
		return 0, ErrGasUintOverflow
	}

	return callCost.Uint64(), nil
}
```
The ````base```` gas is calculated in ````gasCall()```` of ````gas_table.go````,  which is subject to
```solidity
(1) L370~L376: call to a new account
(2) L377~L379: call with non zero value
(3) L380~L383: memory expansion
```
The ````(1)```` and ````(3)```` are irrelevant  in this case, but ````(2)```` should be taken into account.

https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/core/vm/gas_table.go#L364
```go
File: core\vm\gas_table.go
364: func gasCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
365: 	var (
366: 		gas            uint64
367: 		transfersValue = !stack.Back(2).IsZero()
368: 		address        = common.Address(stack.Back(1).Bytes20())
369: 	)
370: 	if evm.chainRules.IsEIP158 {
371: 		if transfersValue && evm.StateDB.Empty(address) {
372: 			gas += params.CallNewAccountGas
373: 		}
374: 	} else if !evm.StateDB.Exist(address) {
375: 		gas += params.CallNewAccountGas
376: 	}
377: 	if transfersValue {
378: 		gas += params.CallValueTransferGas
379: 	}
380: 	memoryGas, err := memoryGasCost(mem, memorySize)
381: 	if err != nil {
382: 		return 0, err
383: 	}
384: 	var overflow bool
385: 	if gas, overflow = math.SafeAdd(gas, memoryGas); overflow {
386: 		return 0, ErrGasUintOverflow
387: 	}
388: 
389: 	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
390: 	if err != nil {
391: 		return 0, err
392: 	}
393: 	if gas, overflow = math.SafeAdd(gas, evm.callGasTemp); overflow {
394: 		return 0, ErrGasUintOverflow
395: 	}
396: 	return gas, nil
397: }
```

The ````raw```` extra gas for transferring value is
```solidity
params.CallValueTransferGas - params.CallStipend * 64 / 63 = 9000 - 2300 * 64 / 63 = 6664
```
releated LOCs:
https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/params/protocol_params.go#L30
https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/params/protocol_params.go#L37
https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/core/vm/instructions.go#L681-L684


### Secondly, EIP-2929 also affects the gas cost of ````CALL```` opcode.
Let's look at the implementation of EIP-2929 on ````CALL```` opcode, the ````ColdAccountAccessCostEIP2929 ```` is 2600 and the ````WarmStorageReadCostEIP2929```` is 100, they are subtracted before applying ````63/64```` rule too.
https://github.com/ethereum/go-ethereum/blob/2adce0b06640aa665706d014a92cd06f0720dcab/core/vm/operations_acl.go#L160
```go
File: core\vm\operations_acl.go
195: 	gasCallEIP2929         = makeCallVariantGasCallEIP2929(gasCall)

File: core\vm\operations_acl.go
160: func makeCallVariantGasCallEIP2929(oldCalculator gasFunc) gasFunc {
161: 	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
162: 		addr := common.Address(stack.Back(1).Bytes20())
163: 		// Check slot presence in the access list
164: 		warmAccess := evm.StateDB.AddressInAccessList(addr)
165: 		// The WarmStorageReadCostEIP2929 (100) is already deducted in the form of a constant cost, so
166: 		// the cost to charge for cold access, if any, is Cold - Warm
167: 		coldCost := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
168: 		if !warmAccess {
169: 			evm.StateDB.AddAddressToAccessList(addr)
170: 			// Charge the remaining difference here already, to correctly calculate available
171: 			// gas for call
172: 			if !contract.UseGas(coldCost) {
173: 				return 0, ErrOutOfGas
174: 			}
175: 		}
176: 		// Now call the old calculator, which takes into account
177: 		// - create new account
178: 		// - transfer value
179: 		// - memory expansion
180: 		// - 63/64ths rule
181: 		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
182: 		if warmAccess || err != nil {
183: 			return gas, err
184: 		}
185: 		// In case of a cold access, we temporarily add the cold charge back, and also
186: 		// add it to the returned gas. By adding it to the return, it will be charged
187: 		// outside of this function, as part of the dynamic gas, and that will make it
188: 		// also become correctly reported to tracers.
189: 		contract.Gas += coldCost
190: 		return gas + coldCost, nil
191: 	}
192: }

```

Here is a test script to show the impact of the two aspects mentioned above
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import "forge-std/Test.sol";
import "forge-std/console.sol";

library SafeCall {
    function callWithMinGas(
        address _target,
        uint256 _minGas,
        uint256 _value,
        bytes memory _calldata
    ) internal returns (bool) {
        bool _success;
        uint256 gasSent;
        assembly {
            // Assertion: gasleft() >= ((_minGas + 200) * 64) / 63
            //
            // Because EIP-150 ensures that, a maximum of 63/64ths of the remaining gas in the call
            // frame may be passed to a subcontext, we need to ensure that the gas will not be
            // truncated to hold this function's invariant: "If a call is performed by
            // `callWithMinGas`, it must receive at least the specified minimum gas limit." In
            // addition, exactly 51 gas is consumed between the below `GAS` opcode and the `CALL`
            // opcode, so it is factored in with some extra room for error.
            if lt(gas(), div(mul(64, add(_minGas, 200)), 63)) {
                // Store the "Error(string)" selector in scratch space.
                mstore(0, 0x08c379a0)
                // Store the pointer to the string length in scratch space.
                mstore(32, 32)
                // Store the string.
                //
                // SAFETY:
                // - We pad the beginning of the string with two zero bytes as well as the
                // length (24) to ensure that we override the free memory pointer at offset
                // 0x40. This is necessary because the free memory pointer is likely to
                // be greater than 1 byte when this function is called, but it is incredibly
                // unlikely that it will be greater than 3 bytes. As for the data within
                // 0x60, it is ensured that it is 0 due to 0x60 being the zero offset.
                // - It's fine to clobber the free memory pointer, we're reverting.
                mstore(
                    88,
                    0x0000185361666543616c6c3a204e6f7420656e6f75676820676173
                )

                // Revert with 'Error("SafeCall: Not enough gas")'
                revert(28, 100)
            }

            // The call will be supplied at least (((_minGas + 200) * 64) / 63) - 49 gas due to the
            // above assertion. This ensures that, in all circumstances, the call will
            // receive at least the minimum amount of gas specified.
            // We can prove this property by solving the inequalities:
            // ((((_minGas + 200) * 64) / 63) - 49) >= _minGas
            // ((((_minGas + 200) * 64) / 63) - 51) * (63 / 64) >= _minGas
            // Both inequalities hold true for all possible values of `_minGas`.
            gasSent := gas() // @audit this operation costs 2 gas
            _success := call(
                gas(), // gas
                _target, // recipient
                _value, // ether value
                add(_calldata, 32), // inloc
                mload(_calldata), // inlen
                0x00, // outloc
                0x00 // outlen
            )
        }
        console.log("gasSent =", gasSent);
        return _success;
    }
}

contract Callee {
    fallback() external payable {
        uint256 gas = gasleft();
        console.log("gasReceived =", gas);
    }
}

contract Caller {
    function execute(
        address _target,
        uint256 _minGas,
        bytes memory _calldata
    ) external payable {
        SafeCall.callWithMinGas(_target, _minGas, msg.value, _calldata);
    }
}

contract TestCallWithMinGas is Test {
    address callee;
    Caller caller;

    function setUp() public {
        callee = address(new Callee());
        caller = new Caller();
    }

    function testCallWithMinGas() public {
        console.log("-------1st call------");
        caller.execute{gas: 64_855}(callee, 63_000, "");

        console.log("\n  -------2nd call------");
        caller.execute{gas: 64_855}(callee, 63_000, "");

        console.log("\n  -------3rd call------");
        caller.execute{gas: 62_555, value: 1}(callee, 63_000, "");
    }
}

```

And the log would be
```solidity
Running 1 test for test/TestCallWithMinGas.sol:TestCallWithMinGas
[PASS] testCallWithMinGas() (gas: 36065)
Logs:
  -------1st call------
  gasReceived = 60582
  gasSent = 64200

  -------2nd call------
  gasReceived = 63042
  gasSent = 64200

  -------3rd call------
  gasReceived = 56483
  gasSent = 64200
```
The difference between ````1st call```` and ````2nd call```` is caused by EIP-2929, and the difference between ````2nd call```` and ````3rd call```` is caused by transferring value. We can see the actual received gas in the sub-contract is less than the 63,000 ````_minGas```` limit in both 1st and 3rd call.

## Impact
````SafeCall.callWithMinGas()```` is a key design to ensure withdrawal transactions will be executed with more gas than the limit specified by users. This issue breaks the specification. Finalizing withdrawal transactions with less than specified gas limit may fail unexpectedly due to out of gas, lead to loss of funds.

## Code Snippet
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L48

## Tool used

Manual Review

## Recommendation
The migration logic may look like
```solidity
if (_value == 0) {
     gasleft() >= ((_minGas + 200) * 64) / 63 + 2600
} else {
     gasleft() >= ((_minGas + 200) * 64) / 63 + 2600 + 6700
}
```



## Discussion

**GalloDaSballo**

The math checks out, the base-gas is ignoring CALL + Cold Address meaning that there are scenarios in which base gas is not sufficient

**hrishibhat**

Sponsor comment:
This report is valid. The formula used in `SafeCall.callWithMinGas()` does not account for all of the dynamic gas costs of the `CALL` opcode.

**GalloDaSballo**

The finding shows the full impact, agree with High Severity

# Issue M-1: CrossDomainMessenger does not successfully guarantee replayability, can lose user funds 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/96 

## Found by 
obront

## Summary

While `SafeCall.callWithMinGas` successfully ensures that the called function will not revert, it does not ensure any remaining buffer for continued execution on the calling contract.

As a result, there are situations where `OptimismPortal` can be called with an amount of gas such that the remaining gas after calling `L1CrossDomainMessenger` is sufficient to finalize the transaction, but such that the remaining gas after `L1CrossDomainMessenger` makes its call to target is insufficient to mark the transaction as successful or failed.

In any of these valid scenarios, users who withdraw using the L1CrossDomainMessenger (expecting replayability) will have their withdrawals bricked, permanently losing their funds.

## Vulnerability Detail

When a user performs a withdrawal with the `L1CrossDomainMessenger`, they include a `gasLimit` value, which specifies the amount of gas that is needed for the function to execute on L1.

This value is translated into two separate values:

1) The `OptimismPortal` sends at least `baseGas(_message, _minGasLimit) = 64/63 * _minGasLimit + 16 * data.length + 200_000` to `L1CrossDomainMessenger`, which accounts for the additional overhead used by the Cross Domain Messenger.

2) The `L1CrossDomainMessenger` sends at least `_minGasLimit` to the target contract.

The core of this vulnerability is in the fact that, if:
- `OptimismPortal` retains sufficient gas after its call to complete the transaction, and
- `L1CrossDomainMessenger` runs out of gas after its transaction is complete (even if the tx succeeded)

...then the result will be that the transaction is marked as finalized in the Portal (disallowing it from being called again), while the Cross Domain Messenger transaction will revert, causing the target transaction to revert and not setting it in `failedMessages` (disallowing it from being replayed). The result is that the transaction will be permanently stuck.

## Calcuations

Let's run through the math to see how this might unfold. We will put aside the additional gas allocated for calldata length, because this amount is used up in the call and doesn't materially impact the calculations.

When the `OptimismPortal` calls the `L1CrossDomainMessenger`, it is enforced that the gas sent will be greater than or equal to `_minGasLimit * 64/63 + 200_000`.

This ensures that the remaining gas for the `OptimismPortal` to continue execution after the call is at least `_minGasLimit / 64 + 3125`. Even assuming that `_minGasLimit == 0`, this is sufficient for `OptimismPortal` to complete execution, so we can safely say that any time `OptimismPortal.finalizeWithdrawalTransaction()` is called with sufficient gas to pass the `SafeCall.callWithMinGas()` check, it will complete execution.

Moving over to `L1CrossDomainMessenger`, our call begins with at least `_minGasLimit * 64/63 + 200_000` gas. By the time we get to the external call, we have remaining gas of at least `_minGasLimit * 64/63 + 158_998`. This leaves us with the following guarantees:

1) Gas available for the external call will be at least 63/64ths of that, which equals `_minGasLimit + 156_513`.
2) Gas available for continued execution after the call will be at least 1/64th of that, which equals `_minGasLimit * 1/63 + 3125`.

The additional gas required to mark the transaction as `failedMessages[versionedHash] = true` and complete the rest of the execution is `23,823`.

Therefore, in any situation where the external call uses all the available gas will revert if `_minGasLimit * 1/63 + 3125 < 23_823`, which simplifies to `_minGasLimit < 1_303_974`. In other words, in most cases.

However, it should be unusual for the external call to use all the available gas. In most cases, it should only use `_minGasLimit`, which would leave `156_513` available to resolve this issue.

So, let's look at some examples of times when this may not be the case.

## At Risk Scenarios

There are several valid scenarios where users might encounter this issue, and have their replayable transactions stuck:

### User Sends Too Little Gas

The expectation when using the Cross Domain Messenger is that all transactions will be replayable. Even if the `_minGasLimit` is set incorrectly, there will always be the opportunity to correct this by replaying it yourself with a higher gas limit. In fact, it is a core tenet of the Cross Domain Messengers that they include replay protection for failed transactions.

However, if a user sets a gas limit that is too low for a transaction, this issue may result.

The consequence is that, while users think that Cross Domain Messenger transactions are replayable and gas limits don't need to be set precisely, they can in fact lose their entire withdrawal if they set their gas limit too low, even when using the "safe" Standard Bridge or Cross Domain Messenger.

### Target Contract Uses More Than Minimum Gas

The checks involved in this process ensure that sufficient gas is being sent to a contract, but there is no requirement that that is all the gas a contract uses.

`_minGasLimit` should be set sufficiently high for the contract to not revert, but that doesn't mean that `_minGasLimit` represents the total amount of gas the contract uses.

As a silly example, let's look at a modified version of the `gas()` function in your `Burn.sol` contract:
```solidity
function gas(uint256 _amountToLeave) internal view {
    uint256 i = 0;
    while (gasleft() > _amountToLeave) {
        ++i;
    }
}
```
This function runs until it leaves a specified amount of gas, and then returns. While the amount of gas sent to this contract could comfortably exceed the `_minGasLimit`, it would not be safe to assume that the amount leftover afterwards would equal `startingGas - _minGasLimit`.

While this is a contrived example, but the point is that there are many situations where it is not safe to assume that the minimum amount of gas a function needs will be greater than the amount it ends up using, if it is provided with extra gas.

In these cases, the assumption that our leftover gas after the function runs will be greater than the required 1/64th does not hold, and the withdrawal can be bricked.

## Impact

In certain valid scenarios where users decide to use the "safe" Cross Domain Messenger or Standard Bridge with the expectation of replayability, their withdrawals from L2 to L1 can be bricked and permanently lost.


## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L315-L412

https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L291-L383


## Tool used

Manual Review

## Recommendation

`L1CrossDomainMessenger` should only send `_minGasLimit` along with its call to the target (rather than `gas()`) to ensure it has sufficient leftover gas to ensure replayability.




## Discussion

**hrishibhat**

Sponsor comment:
 Tentatively marking this as medium for several reasons. First, this issue can only be encountered through user misconfiguration. If a sufficient minimum gas limit is supplied to the withdrawal transaction, it won't occur. However, it is a valid issue and it does break the CrossDomainMessenger's replayability guarantee.

**GalloDaSballo**

Agree with Medium, because reliant on the specific tx type as well as the user mistake

Agree with maintaining Medium because the code's goal is to ensure replayability even if the tx run OOG, expectation which the POC shows can be broken

**GalloDaSballo**

Made #5 primary


**zobront**

Escalate for 10 USDC

This was dup'd with #5, but they appear to be different issues.

#5 focuses on the risks of long message data increasing gas costs. This is more of an obscure edge case (and has a live escalation about the validity of their hash function assumptions, which I don't have an opinion on.)

However, this is a separate issue, which focuses on the risks around gas usage in the target contract and how it can break the replayability guarantee.

**sherlock-admin**

 > Escalate for 10 USDC
> 
> This was dup'd with #5, but they appear to be different issues.
> 
> #5 focuses on the risks of long message data increasing gas costs. This is more of an obscure edge case (and has a live escalation about the validity of their hash function assumptions, which I don't have an opinion on.)
> 
> However, this is a separate issue, which focuses on the risks around gas usage in the target contract and how it can break the replayability guarantee.

You've created a valid escalation for 10 USDC!

To remove the escalation from consideration: Delete your comment.

You may delete or edit your escalation comment anytime before the 48-hour escalation window closes. After that, the escalation becomes final.

**hrishibhat**

Escalation accepted

Considering this issue a separate valid medium

**sherlock-admin**

> Escalation accepted
> 
> Considering this issue a separate valid medium

This issue's escalations have been accepted!

Contestants' payouts and scores will be updated according to the changes made on this issue.

# Issue M-2: Gas usage of cross-chain messages is undercounted, causing discrepancy between L1 and L2 and impacting intrinsic gas calculation 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/88 

## Found by 
Jeiwan

## Summary
Gas consumption of messages sent via [CrossDomainMessenger](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L114) (including both [L1CrossDomainMessenger](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/L1CrossDomainMessenger.sol#L16) and [L2CrossDomainMessenger](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L2/L2CrossDomainMessenger.sol#L18)) is calculated incorrectly: the gas usage of the "relayMessage" wrapper is not counted. As a result, the actual gas consumption of sending a message will be higher than expected. Users will pay less for gas on L1, and L2 blocks may be filled earlier than expected. This will also affect gas metering via [ResourceMetering](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L15): metered gas will be lower than actual consumed gas, and the EIP-1559-like gas pricing mechanism won't reflect the actual demand for gas.
## Vulnerability Detail
The [CrossDomainMessenger.sendMessage](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L247) function is used to send cross-chain messages. Users are required to set the `_minGasLimit` argument, which is the expected amount of gas that the message will consume on the other chain. The function also [computes](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258) the amount of gas required to pass the message to the other chain: this is done in the [baseGas](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258) function, which [computes the byte-wise cost of the message](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L432). `CrossDomainMessenger` also allows users to replay their messages on the destination chain if they failed: to allow this, the contract [wraps user messages in `relayMessage` calls](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L260-L268). This increases the size of messages, but the `baseGas` call above counts gas usage of only the original, not wrapped in the `relayMessage` call, message.

This contradicts the [intrinsic gas calculation in `op-geth`](https://github.com/ethereum-optimism/op-geth/blob/optimism/core/state_transition.go#L75-L108), which calculates gas of an entire message data:
```go
dataLen := uint64(len(data))
// Bump the required gas by the amount of transactional data
if dataLen > 0 {
    ...
}
```
Thus, there's a discrepancy between the contract and the node, which will result in the node consuming more gas than users paid for.

This behaviour also disagrees with how the migration process works:
1. when [migrating pre-Bedrock withdrawals](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L55), `data` is the [entire messages](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L73-L81), including the `relayMessage` calldata;
1. the gas limit of migrated messages is [computed on the entire data](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L86).

Taking into account the logic of paying cross-chain messages' gas consumption on L1, I think the implementation in the migration code is correct and the implementation in `CrossDomainMessenger` is wrong: users should pay for sending the entire cross-chain message, not just the calldata that will be execute on the recipient on the other chain.
## Impact
Since the `CrossDomainMessenger` contract is recommended to be used as the main cross-chain messaging contract and since it's used by both L1 and L2 bridges (when bridging [ETH](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L377-L387) or [ERC20 tokens](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L427-L442)), the undercounted gas will have a broad impact on the system. It'll create a discrepancy in gas usage and payment on L1 and L2: on L1, users will pay for less gas than actually will be consumed by cross-chain messages.

Also, since messages sent from L1 to L2 (via [OptimismPortal.depositTransaction](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L426)) are priced using an EIP-1559-like mechanism (via [ResourceMetering._metered](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L92)), the mechanism will fail to detect the actual demand for gas and will generally set lower gas prices, while actual gas consumption will be higher.

The following bytes are excluded from gas usage counting:
1. the [4 bytes of the `relayMessage` selector](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L261);
1. the [32 bytes of the message nonce](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L262);
1. the [address of the sender](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L263) (20 bytes);
1. the [address of the recipient](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L264) (20 bytes);
1. the [amount of ETH sent with the message](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L265) (32 bytes);
1. the [minimal gas limit of the nested message](https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L266) (32 bytes).

Thus, every cross-chain message sent via the bridge or the messenger will contain 140 bytes that won't be paid by users. The bytes will however be processed by the node and accounted in the gas consumption.
## Code Snippet
1. CrossDomainMessenger.sendMessage sends cross-chain messages:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L247
1. `CrossDomainMessenger.sendMessage` wraps cross-chain messages in `relayMessage` calls:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L260-L268
1. The gas limit counting of cross-chain messages includes only the length of the nested message and doesn't include the `relayMessage` wrapping:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258
1. When pre-Bedrock withdrawals are migrated, gas limit calculation does include the `relayMessage` wrapping:
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/op-chain-ops/crossdomain/migrate.go#L73-L86
## Tool used
Manual Review
## Recommendation
When counting gas limit in the `CrossDomainMessenger.sendMessage` function, consider counting the entire message, including the `relayMessage` calldata wrapping. Consider a change like that:
```diff
diff --git a/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol b/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol
index f67021010..5239feefd 100644
--- a/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol
+++ b/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol
@@ -253,19 +253,20 @@ abstract contract CrossDomainMessenger is
         // message is the amount of gas requested by the user PLUS the base gas value. We want to
         // guarantee the property that the call to the target contract will always have at least
         // the minimum gas limit specified by the user.
+        bytes memory wrappedMessage = abi.encodeWithSelector(
+            this.relayMessage.selector,
+            messageNonce(),
+            msg.sender,
+            _target,
+            msg.value,
+            _minGasLimit,
+            _message
+        );
         _sendMessage(
             OTHER_MESSENGER,
-            baseGas(_message, _minGasLimit),
+            baseGas(wrappedMessage, _minGasLimit),
             msg.value,
-            abi.encodeWithSelector(
-                this.relayMessage.selector,
-                messageNonce(),
-                msg.sender,
-                _target,
-                msg.value,
-                _minGasLimit,
-                _message
-            )
+            wrappedMessage
         );

         emit SentMessage(_target, msg.sender, _message, messageNonce(), _minGasLimit);
```



## Discussion

**hrishibhat**

Sponsor comment:
This should improve gas estimation but is low in severity since it does not affect usage or impact the intended functionality.

**GalloDaSballo**

Would judge in the same way as #77 the incorrect math can lead to an issue

**GalloDaSballo**

I see this as logically equivalent to #77 so I believe it should be awarded as Med

**GalloDaSballo**

This can also be quantified as 
`140 * 16 = 2240`
All l1 -> l2 tx are underpriced by that amount (roughly 10% of fixed base cost)

**GalloDaSballo**

Can see this being escalated against because it's "only" 10% incorrect, but find hard to argue against the math not being correct

# Issue M-3: Malicious actor can prevent migration by calling a non-existing function in `OVM_L2ToL1MessagePasser` and making `ReadWitnessData` return an error 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/67 

## Found by 
0xdeadbeef

## Summary

There is a mismatch between collected witness data in l2geth to the parsing of the collected data during migration.
The mismatch will return an error and halt the migration until the data will be cleaned. 

## Vulnerability Detail

Witness data is collected from L2geth using a state dumper that collects any call to `OVM_L2ToL1MessagePasser`.
The data is collected regardless of the calldata itself. Any call to `OVM_L2ToL1MessagePasser` will be collected.
The data will persist regardless of the status of the transaction.

https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/l2geth/core/vm/evm.go#L206-L209
```solidity
 func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) { 
 	if addr == dump.MessagePasserAddress { 
 		statedumper.WriteMessage(caller.Address(), input) 
 	} 
```

The data will be stored in a file in the following format:
"MSG|\<source\>|\<calldata\>"

At the start of the migration process, in order to unpack the message from the calldata, the code uses the first 4 bytes to lookup the the selector of  `passMessageToL1` from the calldata and unpack the calldata according to the ABI. 

`ReadWitnessData`:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/op-chain-ops/crossdomain/witness.go#L81-L89
```solidity
	method, err := abi.MethodById(msgB[:4])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get method: %w", err)
	}

	out, err := method.Inputs.Unpack(msgB[4:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack: %w", err)
	}
```

As can be seen above, the function will return an error that is bubbled up to stop the migration if:
1. The calldata first 4 bytes is not a selector of a function from the ABI of `OVM_L2ToL1MessagePasser`
2. The parameters encoded with the selectors are not unpackable (are not the parameters specified by the ABI)

A malicious actor will call any non-existing function in the address of `OVM_L2ToL1MessagePasser`.
The message will be stored in the witness data and cause an error during migration.

`ReadWitnessData` is called to parse they json witness data before any filtering is in place. 

## Impact

An arbitrary user can halt the migration process

## Code Snippet

In vulnerability section

## Tool used

Manual Review

## Recommendation

Instead of bubbling up an error, simply continue to the next message.
This shouldn't cause a problem since in the next stages of the migration there are checks to validate any missing messages from the storage.



## Discussion

**hrishibhat**

Sponsor comment:
 Invalid witness data can cause an error during migration by malicious actor call to the OVM_L2ToL1MessagePasser.

**GalloDaSballo**

Temporary DOS, not acceptable risk, agree with Med

# Issue M-4: Usage of **revert** in case of low gas in `L1CrossDomainMessenger` can result in loss of fund 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/27 

## Found by 
HE1M

## Summary

I am reporting this issue separate from my other report `Causing users lose fund if bridging long message from L2 to L1 due to uncontrolled out-of-gas error`, as I think they provide different attack surface and vulnerability.

In the previous report, it is explained that if the forwarded gas passes the gas condition in `OptimismPortal`, but goes out of gas  in `L1CrossDomainMessenger`, it will result in loss of fund since `baseGas` does not consider the effect of memory expansion.

But, in this report, I am going to explain that due to usage of `revert` opcode instead of `return`, users can lose fund if for any reason the gas left is not meeting the condition in `L1CrossDomainMessenger`.

In other words, there is a check for the amount of gas provided in `callWithMinGas`. This check is invoked twice: One in `OptimismPortal.finalizeWithdrawalTransaction` and one in  `L1CrossDomainMessenger.relayMessage`. If the first check is passed, and the second check is not passed, the users' withdrawal transactions are considered as finalized, but not considered as failed message. So, they can not replay their withdrawal transactions.

## Vulnerability Detail

Suppose Alice (an honest user) intends to bridge a message from L2 to L1 by calling `sendMessage`:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L247

The amount of required gas is calculated in the function `baseGas`:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L258
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L423

Suppose some time is passed, and an EIP is proposed so that the gas consumption of some opcodes are changed. During this time, still Alice's withdrawal transaction is not executed on L1 yet.

Bob (the attacker), after proving the Alice's withdrawal transaction and passing the challenge period, calls `finalizeWithdrawalTransaction` to finalize Alice's withdrawal transaction.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L315

Bob provides the the required gas calculated by `baseGas` function on L2. This amount of gas passes the check in `OptimimPortal`. So, the mapping `finalizedWithdrawals` is set to true.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L397
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L64
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L383

And the left gas will be forwarded to `L1CrossDomainMessenger` calling `relayMessage`.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L291

Suppose for any reason (like what assumed above: an EIP was proposed and it changed some opcodes gas), the gas consumption in `relayMessage` is more than expected, so that it does not pass gas condition:
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L361
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L64

Since, it does not pass the gas condition, it will revert in [Line 82](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82).

But, the revert here (in `L1CrossDomainMessenger.relayMessage`) is not correct. Because, the whole transaction of `relayMessage` will be reverted so it will **not** set the flag `failedMessages[versionedHash]` as `true`.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L368

Since, the withdrawal transaction is set as finalized in `OptimismPortal` but not set as failed in `L1CrossDomainMessenger`, it can not be replayed, and Alice loses her fund.


## Impact
Causing users lose fund.

## Code Snippet

## Tool used

Manual Review

## Recommendation

I would say that the `callWithMinGas` should return `false` instead of `revert` when called during `L1CrossDomainMessenger.relayMessage` if the condition of required gas is not met. The following modification in `L1CrossDomainMessenger.relayMessage` is recommended.
```solidity
function relayMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    ) external payable {
        // ...
        //bool success = SafeCall.callWithMinGas(_target, _minGasLimit, _value, _message);
        bool success;
        bytes memory _calldata = _message;
        if (gasleft() >= ((_minGasLimit + 200) * 64) / 63) {
            assembly {
                success := call(
                    gas(), // gas
                    _target, // recipient
                    _value, // ether value
                    add(_calldata, 32), // inloc
                    mload(_calldata), // inlen
                    0x00, // outloc
                    0x00 // outlen
                )
            }
        }
        // ...
    }
```



## Discussion

**maurelian**

This one is tricky. 
The recommendation is a good one, and we agree that it is better to avoid reverting on this code path, however it is also speculative as it depends on some future gas schedule changes and lacks a PoC.

**GalloDaSballo**

Per the rules:
<img width="774" alt="Screenshot 2023-04-18 at 09 51 40" src="https://user-images.githubusercontent.com/13383782/232709388-8822f20d-152b-4e0a-bec6-463c5e228544.png">
<img width="778" alt="Screenshot 2023-04-18 at 09 51 59" src="https://user-images.githubusercontent.com/13383782/232709479-c6c8f02d-febb-4c09-be59-ad52e4886328.png">


I don't think the pre-conditions"have a reasonable chance of becoming true in the future", as this would require:
- Computing incorrect limit
- Waiting for Hardfork
- Hardfork does change CALL / base level costs (risk of every `transfer` contract being bricked)
- User is oblivious and doesn't fix
- Relaying (and getting griefed)

**GalloDaSballo**

Recommend: Closing as invalid

**HE1M**

Escalate for 10 USDC

Using **revert** in `L1CrossDomainMessenger` clearly breaks the replayability guarantee of the project.
In the report it is mentioned that:
>due to usage of revert opcode instead of return, users can lose fund if for any reason the gas left is not meeting the condition in L1CrossDomainMessenger

I agree with your comment regarding Future issues, but the EIP proposed assumption, is just an example for better understanding.

In other words, the project tried to estimate the gas consumption accurately enough when crossing the message from L2 to L1, so that correct amount of gas is forwarded to the target. If, in the middle something happens, there is replayability mechanism to guarantee that the users are able to retry their withdrawal. But, due to this wrong usage of **revert** all those efforts can be broken, and users' fund can be lost.


Please also note that providing a scenario to reach to the [**revert**](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82) opcode in `L1CrossDomainMessenger.relayMessage` should be considered as a separate bug, because there were lots of effort to calculate the correct gas estimation. So, reaching to this [line of code](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82) means that something is broken in the middle.

For example, due to math miscalculation of the gas (as reported in this contest like: #40 #5 , ...) the **revert** is reachable and can result to loss of fund. But, if **revert** was not used, the message would be considered as failed, and the tx would be able to be replayed. So, other bugs would have less impact.

All in all, this wrong usage of **revert** is a bug besides other bugs (math miscalculations) that lead to reaching to this [line of code](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82).

For example, in the following function `sampleFunction`, there are lots of processing in `Part A` to ensure that `x` is bigger than `10`. If `x` is lower than 10, `Part B` is reachable and will be executed.

```solidity
function sampleFunction() {
        // Part A: all the processing to ensure x is bigger than 10
        if(x < 10){
            // Part B: some other processing
        }
        // remaining of the code
    }
```

In this sample code, there are two ways to find bug:

1. Finding a bug in `Part A` that leads to `x` lower than 10
2. Finding a bug in `Part B`

You can replace, the `gasLeft()` with `x`, `10` with `((_minGasLimit + 200) * 64) / 63)`, `Part A` with all the math calculations for the gas estimation, and `Part B` with the [lines](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L65-L82).

In this report, I found a bug in `Part B` which should be considered separate from the bug related to `Part A`.

**sherlock-admin**

 > Escalate for 10 USDC
> 
> Using **revert** in `L1CrossDomainMessenger` clearly breaks the replayability guarantee of the project.
> In the report it is mentioned that:
> >due to usage of revert opcode instead of return, users can lose fund if for any reason the gas left is not meeting the condition in L1CrossDomainMessenger
> 
> I agree with your comment regarding Future issues, but the EIP proposed assumption, is just an example for better understanding.
> 
> In other words, the project tried to estimate the gas consumption accurately enough when crossing the message from L2 to L1, so that correct amount of gas is forwarded to the target. If, in the middle something happens, there is replayability mechanism to guarantee that the users are able to retry their withdrawal. But, due to this wrong usage of **revert** all those efforts can be broken, and users' fund can be lost.
> 
> 
> Please also note that providing a scenario to reach to the [**revert**](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82) opcode in `L1CrossDomainMessenger.relayMessage` should be considered as a separate bug, because there were lots of effort to calculate the correct gas estimation. So, reaching to this [line of code](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82) means that something is broken in the middle.
> 
> For example, due to math miscalculation of the gas (as reported in this contest like: #40 #5 , ...) the **revert** is reachable and can result to loss of fund. But, if **revert** was not used, the message would be considered as failed, and the tx would be able to be replayed. So, other bugs would have less impact.
> 
> All in all, this wrong usage of **revert** is a bug besides other bugs (math miscalculations) that lead to reaching to this [line of code](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82).
> 
> For example, in the following function `sampleFunction`, there are lots of processing in `Part A` to ensure that `x` is bigger than `10`. If `x` is lower than 10, `Part B` is reachable and will be executed.
> 
> ```solidity
> function sampleFunction() {
>         // Part A: all the processing to ensure x is bigger than 10
>         if(x < 10){
>             // Part B: some other processing
>         }
>         // remaining of the code
>     }
> ```
> 
> In this sample code, there are two ways to find bug:
> 
> 1. Finding a bug in `Part A` that leads to `x` lower than 10
> 2. Finding a bug in `Part B`
> 
> You can replace, the `gasLeft()` with `x`, `10` with `((_minGasLimit + 200) * 64) / 63)`, `Part A` with all the math calculations for the gas estimation, and `Part B` with the [lines](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L65-L82).
> 
> In this report, I found a bug in `Part B` which should be considered separate from the bug related to `Part A`.

You've created a valid escalation for 10 USDC!

To remove the escalation from consideration: Delete your comment.

You may delete or edit your escalation comment anytime before the 48-hour escalation window closes. After that, the escalation becomes final.

**hrishibhat**

Escalation accepted

After further discussions with the Lead judge and the protocol this issue was considered to be a weak version of #40, hence considering this issue a valid solo medium. 

**sherlock-admin**

> Escalation accepted
> 
> After further discussions with the Lead judge and the protocol this issue was considered to be a weak version of #40, hence considering this issue a valid solo medium. 

This issue's escalations have been accepted!

Contestants' payouts and scores will be updated according to the changes made on this issue.

# Issue M-5: Incorrect calculation of required gas limit during deposit transaction 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/9 

## Found by 
HE1M, unforgiven

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



## Discussion

**GalloDaSballo**

Sidestepping of cost, no loss of principal, agree with Med

# Issue M-6: Causing users lose fund if bridging long message from L2 to L1 due to uncontrolled out-of-gas error 

Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/5 

## Found by 
HE1M

## Summary

If the amount of gas provided during finalizing withdrawal transactions passes the check in `callWithMinGas`, it is not guaranteed that the relaying message transaction does not go out of gas. 
This can happen if the bridged message from L2 to L1 is long enough to increase the gas consumption significantly so that the predicted `baseGas` is not accurate enough.

## Vulnerability Detail

During finalizing withdrawal transaction in `OptimismPortal.sol`, before calling `_tx.target`, it is checked if enough gas is provided `gasleft() >= ((_minGas + 200) * 64) / 63`, otherwise it will be reverted.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L397
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82

So far so good.

Suppose, enough gas is provided, so that check is passed during finalizing withdrawal transaction, and `finalizedWithdrawals[withdrawalHash]` will be set to `true` for this withdrawal hash. 
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L383

If the `_tx.target` is `L1CrossDomainMessenger`, then the function `L1CrossDomainMessenger.relayMessage` will be called. 
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L291

It will again check there is enough gas to call the next target (like bridge or any other receiver address) during relaying the message.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L361

Here, it is not guaranteed to pass `gasleft() >= ((_minGas + 200) * 64) / 63`. If it is not passed, it will **revert**. In other words, it is not guaranteed that the transaction does not go out of gas during relaying the message.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L82

Then the whole transaction of `relayMessage` will be reverted so it will **not** set the flag `failedMessages[versionedHash]` as `true`.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L368

Since the function `relayMessage` is reverted, the low-level call in `OptimismPortal` will set `success` to `false`. Since, this return value is not handled (because of the design decisions), the transaction `OptimismPortal.finalizeWithdrawalTransaction` is executed successfully.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L397

As a result, while the transaction `OptimismPortal.finalizeWithdrawalTransaction` sets the flag `finalizedWithdrawals[withdrawalHash]` as `true`, the flags `failedMessages[versionedHash]` and `successfulMessages[versionedHash]` are `false`. So, the users can not replay their message, and his fund is lost.

**The question is that is there any possibility that `L1CrossDomainMessenger` reverts due to OOG, even though the required gas is calculated in L2 in the function `baseGas`?**

Suppose, `G` is the gas provided to call `OptimismPortal.finalizeWithdrawalTransaction`.  From line 319 to line 396, let's say some gas is consumed. I call it, `K1`. So, the `gasLeft()` when line 397 is called is equal to: `G - K1`
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L319-L396

Suppose enough gas is provided to pass the check in `OptimismPortal`: `G - K1 >= ((_minGas + 200) * 64) / 63`
So, it is necessary to have: `G >= ((_minGas + 200) * 64) / 63 + K1`
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L397
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L64


**Please note** that `_minGas` here is equal to the base gas calculated in L2: `_minGasLimit * (1016/1000) + messageLength * 16 + 200_000` in which, `_minGasLimit` is the amount of gas set by the user to be forwarded to the final receiver on L1.
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L423-L435
So, by replacing `_minGas ` with  `_minGasLimit * (1016/1000) + messageLength * 16 + 200_000`, we have:
`G >= ((_minGasLimit * (1016/1000) + messageLength * 16 + 200_000 + 200) * 64) / 63 + K1`

So, the amount of gas available to `L1CrossDomainMessenger` will be: `(G - K1 - 51)*(63/64)`
Please note this number is based on the estimation of gas consumption explained in the comment:
>> // Because EIP-150 ensures that, a maximum of 63/64ths of the remaining gas in the call
            // frame may be passed to a subcontext, we need to ensure that the gas will not be
            // truncated to hold this function's invariant: "If a call is performed by
            // `callWithMinGas`, it must receive at least the specified minimum gas limit." In
            // addition, exactly 51 gas is consumed between the below `GAS` opcode and the `CALL`
            // opcode, so it is factored in with some extra room for error.

In the function `L1CrossDomainMessenger.relayMessage`, some gas will be consumed from line 299 to line 360. For simplicity, I call this amount of gas `K2 + HashingGas`, i.e. the consumed gas is separated for later explanation. In other words, the **sum of** consumed gas from line 299 to 303 and the consumed gas from line 326 to 360, is called `K2`, and the consumed gas from line 304 to line 325 is called `HashingGas`.
 - ConsumedGas(L299 to L303 + L326 to L360) = `K2`
 https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L299-L303
 https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L326-L360
 - ConsumedGas(L304 to L325) = `HashingGas`
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L304-L325

So, the `gasLeft()` in line [361 ](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L361) will be: `(G - K1 - 51)*(63/64) - K2 - HashingGas`

To pass the condition `gasleft() >= ((_minGas + 200) * 64) / 63` in `L1CrossDomainMessenger`, it is necessary to have:
`(G - K1 - 51)*(63/64) - K2 - HashingGas >= ((_minGas + 200) * 64) / 63`
**Please note** that, `_minGas` here is equal to `_minGasLimit` which is the amount of gas set by the user to be forwarded to the final receiver on L1.
So, after simplification:
`G >= [((_minGasLimit + 200) * 64) / 63 + K2 + HashingGas] *(64/63) + 51 + K1`

All in all:
 - To pass the gas check in `OptimismPortal`:  `G >= ((_minGasLimit * (1016/1000) + messageLength * 16 + 200_000 + 200) * 64) / 63 + K1`
 - To pass the gas check in `L1CrossDomainMessenger`: `G >= [((_minGasLimit + 200) * 64) / 63 + K2 + HashingGas] *(64/63) + 51 + K1`

**If, `G` is between these two numbers (bigger than the first one, and smaller than the second one), it will pass the check in `OptimismPortal`, but it will revert in `L1CrossDomainMessenger`, as a result it is possible to attack.**

Since, K1 and K2 are almost equal to 50_000, after simplification:
 - `G >= (_minGasLimit * (1016/1000) + messageLength * 16 ) * (64 / 63) + 253_378`
 - `G >= (_minGasLimit * (64 / 63) + HashingGas) *(64/63) + 101_051`

So it is necessary to satisfy the following condition to be able to attack (in that case it is possible that the attacker provides gas amount between the higher and lower bound to execute the attack):
(_minGasLimit * (1016/1000) + messageLength * 16 ) * (64 / 63) + 253_378 < (_minGasLimit * (64 / 63) + HashingGas) *(64/63) + 101_051`
After simplification, we have:
`messageLength < (HashingGas - 150_000) / 16`

**Please note** that the `HashingGas` is a function of `messageLength`. In other words, the consumed gas from Line 304 to 325 is a function of `messageLength`, the longer length the higher gas consumption, but the relation is not linear, it is exponential.**

Please consider that if the `version` is equal to zero, the hashing is done twice (one in `hashCrossDomainMessageV0`, and one in `hashCrossDomainMessageV1`):
https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L307-L324

So, for version zero, the condition can be relaxed to:
`messageLength < (HashingGas * 2 - 150_000) / 16`

The calculation shows that if the `messageLength` is equal to 1 mb for version 0, the gas consumed during hashing will be around 23.5M gas (this satisfies the condition above). While, if the `messageLength` is equal to 512 kb for version 0, the gas consumed during hashing will be around  7.3M gas (this does not satisfy the condition above marginally).

A short summary of calculation is:

`messageLength`= 128 kb, `HashingGas for v1`= 508_000, `HahingGas for v0`= 1_017_287, attack **not** possible
`messageLength`= 256 kb, `HashingGas for v1`= 1_290_584, `HahingGas for v0`= 2_581_168, attack **not** possible
`messageLength`= 512 kb, `HashingGas for v1`= 3_679_097, `HahingGas for v0`= 7_358_194, attack **not** possible
`messageLength`= 684 kb, `HashingGas for v1`= 5_901_416, `HahingGas for v0`= 11_802_831, attack **possible**
`messageLength`= 1024 kb, `HashingGas for v1`= 11_754_659, `HahingGas for v0`= 23_509_318, attack **possible**

![image](https://user-images.githubusercontent.com/123448720/230324445-808bcdb7-8247-4349-b8f7-a6e270a0c11b.png)

Which can be calculated approximately by:
```solidity
function checkGasV1(bytes calldata _message)
        public
        view
        returns (uint256, uint256)
    {
        uint256 gas1 = gasleft();
        bytes32 versionedHash = Hashing.hashCrossDomainMessageV1(
            0,
            address(this),
            address(this),
            0,
            0,
            _message
        );
        uint256 gas2 = gasleft();
        return (_message.length, (gas1 - gas2));
    }
```
```solidity
function checkGasV0(bytes calldata _message)
        public
        view
        returns (
            uint256,
            uint256,
            uint256
        )
    {
        uint256 gas1 = gasleft();
        bytes32 versionedHash1 = Hashing.hashCrossDomainMessageV0(
            address(this),
            address(this),
            _message,
            0
        );
        uint256 gas2 = gasleft();
        uint256 gas3 = gasleft();
        bytes32 versionedHash2 = Hashing.hashCrossDomainMessageV1(
            0,
            address(this),
            address(this),
            0,
            0,
            _message
        );
        uint256 gas4 = gasleft();
        return (_message.length, (gas1 - gas2), (gas3 - gas4));
    }
```

It means that if for example the `messageLength` is equal to 684 kb (mostly non-zero, only 42 kb zero), and the message is version 0, and for example the `_minGasLimit` is equal to 21000, an attacker can exploit the user's withdrawal transaction by providing a gas meeting the following condition:
 `(_minGasLimit * (1016/1000) + 684 * 1024 * 16 ) * (64 / 63) + 253_378 < G < (_minGasLimit * (64 / 63) + 11_802_831) *(64/63) + 101_051` 
After, replacing the numbers, the provided gas by the attacker should be: `11_659_592 < G < 12_112_900`
So, by providing almost 12M gas, it will pass the check in `OptimismPortal`, but it will revert in `L1CrossDomainMessenger` due to OOG, as a result the user's transaction will not be allowed to be replayed.

Please note that if there is a long time between request of withdrawal transaction on L2 and finalizing withdrawal transaction on L1, it is possible that the gas price is low enough on L1, so economically reasonable for the attacker to execute it. 

In Summary:

When calculating the `baseGas` on L2, only the `minGasLimit` and `message.length` are considered, and a hardcoded overhead is also added. While, the hashing mechanism (due to memory expansion) is exponentially related to the length of the message. It means that, the amount of gas usage during relaying the message can be increased to the level that is higher than calculated value in `baseGas`. So, if the length of the message is long enough (to increase the gas significantly due to memory expansion), it provides an attack surface so that the attacker provides the amount of gas that only pass the condition in `OptimismPortal`, but goes out of gas in `L1CrossDomainMessenger`.



## Impact
Users will lose fund because it is set as finalized, but not set as failed. So, they can not replay it.

## Code Snippet

## Tool used

Manual Review

## Recommendation

If all the gas is consumed before reaching to [L361](https://github.com/sherlock-audit/2023-03-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L361), the vulnerability is available.
So, it is recommended to include memory expansion effect when calculating `baseGas`.



## Discussion

**hrishibhat**

Sponsor comment:
This is similar to issue #96 whereby a withdrawal with a gas limit configured to be too low can be bricked if the call to the XDM silently fails due to OOG.

**GalloDaSballo**

Making this primary

**ydspa**

Escalate for 10 USDC.

This finding should be invalid. 

It's description for ````HashingGas```` is inaccurate , the gas cost for keccak256 hashing is only ````6 gas per 32 bytes````, which is linear. The primary issue in this case, as illustrated in https://github.com/sherlock-audit/2023-03-optimism-judging/issues/52,  is that the current implementation is missing to consider the dynamic gas cost of memory usage, which is quadratic. Both of the two parts are not ````exponential```` as described in this finding. As opposed to https://github.com/sherlock-audit/2023-03-optimism-judging/issues/52, It's clear that this finding didn't provide full aspects and accurate analysis of the issue.



**sherlock-admin**

 > Escalate for 10 USDC.
> 
> This finding should be invalid. 
> 
> It's description for ````HashingGas```` is inaccurate , the gas cost for keccak256 hashing is only ````6 gas per 32 bytes````, which is linear. The primary issue in this case, as illustrated in https://github.com/sherlock-audit/2023-03-optimism-judging/issues/52,  is that the current implementation is missing to consider the dynamic gas cost of memory usage, which is quadratic. Both of the two parts are not ````exponential```` as described in this finding. As opposed to https://github.com/sherlock-audit/2023-03-optimism-judging/issues/52, It's clear that this finding didn't provide full aspects and accurate analysis of the issue.
> 
> 

You've created a valid escalation for 10 USDC!

To remove the escalation from consideration: Delete your comment.

You may delete or edit your escalation comment anytime before the 48-hour escalation window closes. After that, the escalation becomes final.

**HE1M**

Escalate for 10 USDC

Some points:

1. This report is not duplicate of #96.
2. This report is not dependent on the user's mistake (or misconfiguration). It shows that due to wrong calculation of [`baseGas`](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L423-L435) it does break the CrossDomainMessenger's replayability guarantee in case the user's message is long enough. 
3. The term `HashingGas` is **not** including only the `kecca256`. As it is explained in the report: 
> the consumed gas from line 304 to line 325 is called HashingGas
4. In the report, the working code is provided to show how the gas consumption is dependent to the length of the message.

**sherlock-admin**

 > Escalate for 10 USDC
> 
> Some points:
> 
> 1. This report is not duplicate of #96.
> 2. This report is not dependent on the user's mistake (or misconfiguration). It shows that due to wrong calculation of [`baseGas`](https://github.com/sherlock-audit/2023-03-optimism/blob/0cdcafe158e00766de7fb5bb6ff2055a10b0dc78/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L423-L435) it does break the CrossDomainMessenger's replayability guarantee in case the user's message is long enough. 
> 3. The term `HashingGas` is **not** including only the `kecca256`. As it is explained in the report: 
> > the consumed gas from line 304 to line 325 is called HashingGas
> 4. In the report, the working code is provided to show how the gas consumption is dependent to the length of the message.

You've created a valid escalation for 10 USDC!

To remove the escalation from consideration: Delete your comment.

You may delete or edit your escalation comment anytime before the 48-hour escalation window closes. After that, the escalation becomes final.

**hrishibhat**

Escalation accepted

Accepting the 2nd escalation,
Considering this issue a separate valid medium issue based on the escalation comments

**sherlock-admin**

> Escalation accepted
> 
> Accepting the 2nd escalation,
> Considering this issue a separate valid medium issue based on the escalation comments

This issue's escalations have been accepted!

Contestants' payouts and scores will be updated according to the changes made on this issue.

