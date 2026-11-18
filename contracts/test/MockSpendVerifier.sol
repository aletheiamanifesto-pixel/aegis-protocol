// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev TEST ONLY. Records the public inputs it receives and returns `result`.
contract MockSpendVerifier {
    bool public result = true;
    bytes32[] internal _last;

    function setResult(bool r) external {
        result = r;
    }

    function verify(bytes calldata, bytes32[] calldata publicInputs) external returns (bool) {
        _last = publicInputs;
        return result;
    }

    function lastPublicInputs() external view returns (bytes32[] memory) {
        return _last;
    }
}
