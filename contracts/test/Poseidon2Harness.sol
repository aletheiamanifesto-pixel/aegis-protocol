// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2} from "../lib/Poseidon2.sol";

/// @dev TEST ONLY. Exposes the library to the tests.
contract Poseidon2Harness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return Poseidon2.hash2(a, b);
    }
}
