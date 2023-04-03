0xChinedu

medium

# Use `safeTransferFrom()` Instead of `transferFrom()` for Outgoing ERC721 transfers

## Summary
It is recommended to use safeTransferFrom() instead of transferFrom() when transferring ERC721s
## Vulnerability Detail
The **transferFrom()** method is used instead of **safeTransferFrom()**, which I assume is a gas-saving measure. I however argue that this isn’t recommended because:
- [OpenZeppelin’s documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#IERC721-transferFrom-address-address-uint256-) discourages the use of transferFrom(); use safeTransferFrom() whenever possible.
- The recipient could have logic in the onERC721Received() function, which is only triggered in the safeTransferFrom() function and not in transferFrom(). A notable example of such contracts is the Sudoswap pair:
```solidity
function onERC721Received(
  address,
  address,
  uint256 id,
  bytes memory
) public virtual returns (bytes4) {
  IERC721 _nft = nft();
  // If it's from the pair's NFT, add the ID to ID set
  if (msg.sender == address(_nft)) {
    idSet.add(id);
  }
  return this.onERC721Received.selector;
}
```
- It helps ensure that the recipient is indeed capable of handling ERC721s.
## Impact
While unlikely because the recipient is the contract, there is the potential loss of NFTs should the recipient be unable to handle the sent ERC721s.
## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/9b9f78c6613c6ee53b93ca43c71bb74479f4b975/packages/contracts-bedrock/contracts/L1/L1ERC721Bridge.sol#L101
## Tool used

Manual Review

## Recommendation
Use safeTransferFrom() when sending out the NFT from the '_from' address.
```solidity
- IERC721(_localToken).transferFrom(_from, address(this), _tokenId);
+ IERC721(_localToken).safeTransferFrom(_from, address(this), _tokenId);
```