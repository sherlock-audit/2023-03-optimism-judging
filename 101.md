obront

medium

# LES transactions are not sent to the sequencer

## Summary

LES (Light Ethereum Subprotocol) doesn't forward the transaction to the sequencer when receiving it over RPC.

## Vulnerability Detail

When a user submits a transaction to op-geth node (validator/verifier mode), the node sends the transaction to the sequencer, which adds it to the tx pool.
```go
func (b *EthAPIBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	if b.eth.seqRPCService != nil {
		data, err := tx.MarshalBinary()
		if err != nil {
			return err
		}
		if err := b.eth.seqRPCService.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data)); err != nil {
			return err
		}
	}
	return b.eth.txPool.AddLocal(tx)
}
```

However, in LES mode, It only adds the transaction to the tx pool.
```go
func (b *LesApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.eth.txPool.Add(ctx, signedTx)
}
```



## Impact

- Transction isn't sent to the sequencer and will never be processed (submitted to L1).
- Inconsistency among op-geth nodes validators/verifiers and the sequencer.
- Additionally, from UX perspective, it is misleading as the user would think the transaction was submitted "successfully".

## Code Snippet

https://github.com/ethereum-optimism/op-geth/blob/optimism-history/les/api_backend.go#L193-L195
https://github.com/ethereum-optimism/op-geth/blob/optimism-history/eth/api_backend.go#L253-L264


## Tool used

Manual Review

## Recommendation

Match this RPC change in the LES RPC.

Ref: https://op-geth.optimism.io/

## Additional notes

This finding is inspired by issue #175 in the previous contest. It exists in the repository defined in-scope for the contest and the judge's comment justifying medium severity applies.

`This was an oversight on Optimism's part and there are markers that would suggest it should be in scope.`

Furthermore, it definitely seems like Optimism wishes to support LES mode, as the `les`  directory has been updated 3 weeks ago.
