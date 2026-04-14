// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract ProofMintRegistry is AccessControl, Pausable {
    bytes32 public constant BRAND_ROLE = keccak256("BRAND_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    struct Passport {
        uint256 id;
        string productId;
        bytes32 dppHash;
        address brand;
        uint256 createdAt;
        uint256 updatedAt;
        uint256 version;
        string ipfsCid;
        bool active;
    }

    uint256 public nextPassportId;
    mapping(uint256 => Passport) public passports;
    mapping(string => uint256[]) public productHistory;

    event PassportCreated(uint256 indexed id, string indexed productId, address indexed brand, bytes32 dppHash, string ipfsCid, uint256 version);
    event PassportUpdated(uint256 indexed id, string indexed productId, bytes32 dppHash, string ipfsCid, uint256 version);
    event PassportRevoked(uint256 indexed id, string indexed productId, address indexed revokedBy);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function createPassport(
        string calldata productId,
        bytes32 dppHash,
        string calldata ipfsCid
    ) external onlyRole(BRAND_ROLE) whenNotPaused returns (uint256 passportId) {
        require(bytes(productId).length > 0, "ProofMint: empty productId");
        require(dppHash != bytes32(0), "ProofMint: empty hash");
        require(bytes(ipfsCid).length > 0, "ProofMint: empty cid");

        passportId = ++nextPassportId;

        passports[passportId] = Passport({
            id: passportId,
            productId: productId,
            dppHash: dppHash,
            brand: msg.sender,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            version: 1,
            ipfsCid: ipfsCid,
            active: true
        });

        productHistory[productId].push(passportId);

        emit PassportCreated(passportId, productId, msg.sender, dppHash, ipfsCid, 1);
    }

    function updatePassport(
        uint256 id,
        bytes32 newDppHash,
        string calldata newIpfsCid
    ) external onlyRole(BRAND_ROLE) whenNotPaused {
        Passport storage p = passports[id];
        require(p.id != 0, "ProofMint: missing passport");
        require(p.active, "ProofMint: passport revoked");
        require(p.brand == msg.sender, "ProofMint: not owner");
        require(newDppHash != bytes32(0), "ProofMint: empty hash");
        require(bytes(newIpfsCid).length > 0, "ProofMint: empty cid");

        p.dppHash = newDppHash;
        p.ipfsCid = newIpfsCid;
        p.updatedAt = block.timestamp;
        p.version += 1;

        productHistory[p.productId].push(id);

        emit PassportUpdated(id, p.productId, newDppHash, newIpfsCid, p.version);
    }

    function verifyPassport(uint256 id, bytes32 expectedHash) external view returns (bool) {
        Passport storage p = passports[id];
        if (p.id == 0 || !p.active) {
            return false;
        }
        return p.dppHash == expectedHash;
    }

    function revokePassport(uint256 id) external whenNotPaused {
        Passport storage p = passports[id];
        require(p.id != 0, "ProofMint: missing passport");
        require(p.active, "ProofMint: already revoked");
        require(p.brand == msg.sender || hasRole(AUDITOR_ROLE, msg.sender), "ProofMint: not allowed");

        p.active = false;
        p.updatedAt = block.timestamp;

        emit PassportRevoked(id, p.productId, msg.sender);
    }
}
