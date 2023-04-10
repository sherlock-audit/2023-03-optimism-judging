unforgiven

high

# cross domain messages with big calldata would be not-relay-able because baseGas() overestimate the intrinsic gas

## Summary
Function `baseGas()` use 16 gas per byte for calldata and if user's message has 0 values in it and the calldata was long then the return value of the `baseGas()` would be bigger than 30M and the message can't be finalized in the L1 because of big gas requirement while if the correct intrinsic gas calculated then message would have been successfully finalized in the L1.

## Vulnerability Detail
This is `sendMessage()` code in CrossDomainMessenger:
```solidity
    function sendMessage(
        address _target,
        bytes calldata _message,
        uint32 _minGasLimit
    ) external payable {
        // Triggers a message to the other messenger. Note that the amount of gas provided to the
        // message is the amount of gas requested by the user PLUS the base gas value. We want to
        // guarantee the property that the call to the target contract will always have at least
        // the minimum gas limit specified by the user.
        _sendMessage(
            OTHER_MESSENGER,
            baseGas(_message, _minGasLimit),
            msg.value,
            abi.encodeWithSelector(
                this.relayMessage.selector,
                messageNonce(),
                msg.sender,
                _target,
                msg.value,
                _minGasLimit,
                _message
            )
        );

        emit SentMessage(_target, msg.sender, _message, messageNonce(), _minGasLimit);
        emit SentMessageExtension1(msg.sender, msg.value);

        unchecked {
            ++msgNonce;
        }
    }
```
As you can see it uses `baseGas()` to calculate the required gas for withdrawal (when sending message from L2 to L1) transaction. This is `baseGas()` code:
```solidity
    function baseGas(bytes calldata _message, uint32 _minGasLimit) public pure returns (uint64) {
        // We peform the following math on uint64s to avoid overflow errors. Multiplying the
        // by MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR would otherwise limit the _minGasLimit to
        // type(uint32).max / MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR ~= 4.2m.
        return
            // Dynamic overhead
            ((uint64(_minGasLimit) * MIN_GAS_DYNAMIC_OVERHEAD_NUMERATOR) /
                MIN_GAS_DYNAMIC_OVERHEAD_DENOMINATOR) +
            // Calldata overhead
            (uint64(_message.length) * MIN_GAS_CALLDATA_OVERHEAD) +
            // Constant overhead
            MIN_GAS_CONSTANT_OVERHEAD;
    }
```
As you can see code uses ` (uint64(_message.length) * MIN_GAS_CALLDATA_OVERHEAD)` to calculate withdrawal transaction(in L1) intrinsic gas to make sure the message can be included in the L1 block and cross domain messages would be relayed always. but `MIN_GAS_CALLDATA_OVERHEAD)` is 16 and code would overestimate the intrinsic gas for some of the message where calldata has 0 values in it. this can cause some of the cross domain messages to have big required withdrawal gas which could be bigger than Ethereum block gas limit and those message would be un-relay-able.
This is the scenario:
1. UserA wants to send message from L2 to L1 which the length is 2M bytes but most of the bytes are 0. the message includes payment info that a contract should do in the L1 and UserA sends 100ETH with the message.
2. UserA uses L2CrossDomainMessenger to make sure his message would be replay-able in the L1 and his funds won't get locked in the bridge by some mistake.
3. UserA would call `sendMessage()` with his message in L2 and code would transfer UserA 100ETH and then calculate ~32M required gas for withdrawal transaction and send this message to L1 to be proven and finalized Portal in L1.
4. UserA won't be able to finalize his withdraw message in L1 because the required gas for withdrawal message is bigger than Ethereum block gas limit and userA would lose his funds.
5. while UserA sends a message that can be executed in the L1 because protocol overestimate the intrinsic gas for withdrawal transaction UserA would lose his funds.

in this scenario UserA didn't do anything wrong and didn't user L2CrossDomainMessenger wrong way, UserA sends the normal message that is executable in the L1 by L2CrossDomainMessenger but because code overestimate the intrinsic gas UserA would lose his funds and his message can't be finalized in the L1(Portal).

The L2CrossDomainMessenger is a high-level interface for message passing between L1 and L2 on the L2 side. Users are generally encouraged to use this contract instead of lower level message passing contracts and it's supposed to be safe but this issue make users to lose their funds when their message data is long.

of course this issue would cause the L2StandardBridge and L2ERC721Bridge messages to be broken when the message size is long too and users who use those bridges would lose their funds too without doing anything wrong. (in user point of view sending a 2M data while most of the bytes are 0 is valid thing because that transaction is executable in the Ethereum)

## Impact
User won't receive their messages in L1 while their funds are lock in the L2 and they are used L2CrossDomainMessenger which is supposed to be safe and don't block users messages and funds if users use it. the issue would happen to L2StandardBridge and L2ERC721Bridge messages too.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L423-L435
## Tool used
Manual Review

## Recommendation
calculate intrinsic gas correctly or set max cap(30M) for the required min gas for withdrawal transaction or inform users about this risk.