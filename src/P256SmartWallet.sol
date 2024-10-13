// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Secp256r1} from "./libraries/Secp256r1.sol";

/// @notice Passkey smart contract wallet.
contract P256SmartWallet {
    /// @notice The x coordinate of the authorized public key
    uint256 authorizedPublicKeyX;
    /// @notice The y coordinate of the authorized public key
    uint256 authorizedPublicKeyY;

    /// @notice Internal nonce used for replay protection, must be tracked and included into prehashed message.
    uint256 public nonce;

    /// @notice Sets the passkey that controls this smart wallet.
    constructor(uint256 publicKeyX, uint256 publicKeyY) {
        authorizedPublicKeyX = publicKeyX;
        authorizedPublicKeyY = publicKeyY;
    }

    /// @notice Main entrypoint for authorized transactions. Accepts transaction parameters (to, data, value) and a secp256r1 signature.
    function transact(address to, bytes memory data, uint256 value, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encode(nonce++, to, data, value));
        require(Secp256r1.verify(digest, r, s, authorizedPublicKeyX, authorizedPublicKeyY), "Invalid signature");

        (bool success,) = to.call{value: value}(data);
        require(success);
    }
}
