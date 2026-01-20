// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PKRegistry
 * @notice Meteor-NC Public Key Registry for EVM chains
 * @dev Stores and manages post-quantum public keys (pk_blob = pkSeed || bHash)
 * 
 * Key Features:
 *   - Register/rotate/revoke keys
 *   - Multiple key types (encryption, signing)
 *   - Suite versioning (Level 1/3/5)
 *   - Expiration support
 *   - Only key owner can manage their keys
 * 
 * Key ID Computation:
 *   keyId = keccak256(pkSeed || bHash)
 *   This matches the sender_id/recipient_id in SecureEnvelope
 */
contract PKRegistry {
    
    // =========================================================================
    // Types
    // =========================================================================
    
    /// @notice Key type enumeration
    enum KeyType {
        ENCRYPTION,   // 0: For Meteor-NC KEM encryption
        SIGNING       // 1: For digital signatures (future: Dilithium)
    }
    
    /// @notice Meteor public key structure
    struct MeteorKey {
        bytes32 keyId;        // keccak256(pkSeed || bHash) - matches envelope IDs
        bytes32 pkSeed;       // 32B - seed for matrix A reconstruction
        bytes32 bHash;        // 32B - hash of public key vector b
        uint8 suiteId;        // 0x01 (L1), 0x02 (L3), 0x03 (L5)
        KeyType keyType;      // ENCRYPTION or SIGNING
        uint64 validFrom;     // Registration timestamp
        uint64 validUntil;    // Expiration (0 = no expiry)
        bool revoked;         // Revocation flag
    }
    
    // =========================================================================
    // Storage
    // =========================================================================
    
    /// @notice owner => keyId => MeteorKey
    mapping(address => mapping(bytes32 => MeteorKey)) public keys;
    
    /// @notice owner => keyId[] (list of all keys for an address)
    mapping(address => bytes32[]) public keyIdsByOwner;
    
    /// @notice keyId => owner (reverse lookup)
    mapping(bytes32 => address) public keyOwner;
    
    /// @notice Contract version
    string public constant VERSION = "1.0.0";
    
    // =========================================================================
    // Events
    // =========================================================================
    
    event KeyRegistered(
        address indexed owner,
        bytes32 indexed keyId,
        uint8 suiteId,
        KeyType keyType,
        uint64 validUntil
    );
    
    event KeyRotated(
        address indexed owner,
        bytes32 indexed oldKeyId,
        bytes32 indexed newKeyId
    );
    
    event KeyRevoked(
        address indexed owner,
        bytes32 indexed keyId
    );
    
    // =========================================================================
    // Errors
    // =========================================================================
    
    error KeyAlreadyRegistered(bytes32 keyId);
    error KeyNotFound(bytes32 keyId);
    error NotKeyOwner(bytes32 keyId, address caller);
    error KeyAlreadyRevoked(bytes32 keyId);
    error InvalidSuiteId(uint8 suiteId);
    error InvalidPkBlob();
    
    // =========================================================================
    // Registration
    // =========================================================================
    
    /**
     * @notice Register a new Meteor public key
     * @param pkSeed 32-byte seed for matrix A reconstruction
     * @param bHash 32-byte hash of public key vector b
     * @param suiteId Suite ID (0x01=L1, 0x02=L3, 0x03=L5)
     * @param keyType Key type (ENCRYPTION or SIGNING)
     * @param validUntil Expiration timestamp (0 = no expiry)
     * @return keyId The computed key ID
     */
    function registerKey(
        bytes32 pkSeed,
        bytes32 bHash,
        uint8 suiteId,
        KeyType keyType,
        uint64 validUntil
    ) external returns (bytes32 keyId) {
        // Validate inputs
        if (pkSeed == bytes32(0) || bHash == bytes32(0)) {
            revert InvalidPkBlob();
        }
        if (suiteId < 0x01 || suiteId > 0x03) {
            revert InvalidSuiteId(suiteId);
        }
        
        // Compute keyId = keccak256(pkSeed || bHash)
        keyId = keccak256(abi.encodePacked(pkSeed, bHash));
        
        // Check not already registered
        if (keyOwner[keyId] != address(0)) {
            revert KeyAlreadyRegistered(keyId);
        }
        
        // Store key
        keys[msg.sender][keyId] = MeteorKey({
            keyId: keyId,
            pkSeed: pkSeed,
            bHash: bHash,
            suiteId: suiteId,
            keyType: keyType,
            validFrom: uint64(block.timestamp),
            validUntil: validUntil,
            revoked: false
        });
        
        keyIdsByOwner[msg.sender].push(keyId);
        keyOwner[keyId] = msg.sender;
        
        emit KeyRegistered(msg.sender, keyId, suiteId, keyType, validUntil);
        return keyId;
    }
    
    /**
     * @notice Register key from raw pk_blob bytes
     * @param pkBlob 64-byte pk_blob (pkSeed || bHash)
     * @param suiteId Suite ID
     * @param keyType Key type
     * @param validUntil Expiration timestamp
     * @return keyId The computed key ID
     */
    function registerKeyFromBlob(
        bytes calldata pkBlob,
        uint8 suiteId,
        KeyType keyType,
        uint64 validUntil
    ) external returns (bytes32 keyId) {
        if (pkBlob.length != 64) {
            revert InvalidPkBlob();
        }
        
        bytes32 pkSeed;
        bytes32 bHash;
        
        assembly {
            pkSeed := calldataload(pkBlob.offset)
            bHash := calldataload(add(pkBlob.offset, 32))
        }
        
        return this.registerKey(pkSeed, bHash, suiteId, keyType, validUntil);
    }
    
    // =========================================================================
    // Rotation & Revocation
    // =========================================================================
    
    /**
     * @notice Rotate key: revoke old and register new
     * @param oldKeyId Key ID to revoke
     * @param newPkSeed New pk_seed
     * @param newBHash New b_hash
     * @param newSuiteId New suite ID
     * @param newValidUntil New expiration
     * @return newKeyId The new key ID
     */
    function rotateKey(
        bytes32 oldKeyId,
        bytes32 newPkSeed,
        bytes32 newBHash,
        uint8 newSuiteId,
        uint64 newValidUntil
    ) external returns (bytes32 newKeyId) {
        // Verify ownership
        if (keyOwner[oldKeyId] != msg.sender) {
            revert NotKeyOwner(oldKeyId, msg.sender);
        }
        
        MeteorKey storage oldKey = keys[msg.sender][oldKeyId];
        if (oldKey.revoked) {
            revert KeyAlreadyRevoked(oldKeyId);
        }
        
        // Preserve key type
        KeyType keyType = oldKey.keyType;
        
        // Revoke old key
        oldKey.revoked = true;
        emit KeyRevoked(msg.sender, oldKeyId);
        
        // Register new key (bypass external call for gas efficiency)
        if (newPkSeed == bytes32(0) || newBHash == bytes32(0)) {
            revert InvalidPkBlob();
        }
        if (newSuiteId < 0x01 || newSuiteId > 0x03) {
            revert InvalidSuiteId(newSuiteId);
        }
        
        newKeyId = keccak256(abi.encodePacked(newPkSeed, newBHash));
        
        if (keyOwner[newKeyId] != address(0)) {
            revert KeyAlreadyRegistered(newKeyId);
        }
        
        keys[msg.sender][newKeyId] = MeteorKey({
            keyId: newKeyId,
            pkSeed: newPkSeed,
            bHash: newBHash,
            suiteId: newSuiteId,
            keyType: keyType,
            validFrom: uint64(block.timestamp),
            validUntil: newValidUntil,
            revoked: false
        });
        
        keyIdsByOwner[msg.sender].push(newKeyId);
        keyOwner[newKeyId] = msg.sender;
        
        emit KeyRegistered(msg.sender, newKeyId, newSuiteId, keyType, newValidUntil);
        emit KeyRotated(msg.sender, oldKeyId, newKeyId);
        
        return newKeyId;
    }
    
    /**
     * @notice Revoke a key
     * @param keyId Key ID to revoke
     */
    function revokeKey(bytes32 keyId) external {
        if (keyOwner[keyId] != msg.sender) {
            revert NotKeyOwner(keyId, msg.sender);
        }
        
        MeteorKey storage key = keys[msg.sender][keyId];
        if (key.revoked) {
            revert KeyAlreadyRevoked(keyId);
        }
        
        key.revoked = true;
        emit KeyRevoked(msg.sender, keyId);
    }
    
    // =========================================================================
    // Queries
    // =========================================================================
    
    /**
     * @notice Get key by ID
     * @param keyId Key ID
     * @return key The MeteorKey struct
     */
    function getKey(bytes32 keyId) external view returns (MeteorKey memory key) {
        address owner = keyOwner[keyId];
        if (owner == address(0)) {
            revert KeyNotFound(keyId);
        }
        return keys[owner][keyId];
    }
    
    /**
     * @notice Get pk_blob (pkSeed || bHash) for a key
     * @param keyId Key ID
     * @return pkBlob 64-byte pk_blob
     */
    function getPkBlob(bytes32 keyId) external view returns (bytes memory pkBlob) {
        address owner = keyOwner[keyId];
        if (owner == address(0)) {
            revert KeyNotFound(keyId);
        }
        MeteorKey storage key = keys[owner][keyId];
        return abi.encodePacked(key.pkSeed, key.bHash);
    }
    
    /**
     * @notice Check if key is valid (exists, not revoked, not expired)
     * @param keyId Key ID
     * @return valid True if key is valid
     */
    function isKeyValid(bytes32 keyId) external view returns (bool valid) {
        address owner = keyOwner[keyId];
        if (owner == address(0)) return false;
        
        MeteorKey storage key = keys[owner][keyId];
        if (key.revoked) return false;
        if (key.validUntil != 0 && block.timestamp > key.validUntil) return false;
        
        return true;
    }
    
    /**
     * @notice Get all key IDs for an address
     * @param owner Address to query
     * @return keyIds Array of key IDs
     */
    function getKeyIdsByOwner(address owner) external view returns (bytes32[] memory) {
        return keyIdsByOwner[owner];
    }
    
    /**
     * @notice Get owner of a key
     * @param keyId Key ID
     * @return owner Owner address
     */
    function getKeyOwnerAddress(bytes32 keyId) external view returns (address owner) {
        return keyOwner[keyId];
    }
    
    /**
     * @notice Get active (non-revoked, non-expired) keys for an address
     * @param owner Address to query
     * @return activeKeys Array of active MeteorKey structs
     */
    function getActiveKeys(address owner) external view returns (MeteorKey[] memory activeKeys) {
        bytes32[] storage allKeyIds = keyIdsByOwner[owner];
        uint256 count = 0;
        
        // Count active keys
        for (uint256 i = 0; i < allKeyIds.length; i++) {
            MeteorKey storage key = keys[owner][allKeyIds[i]];
            if (!key.revoked && (key.validUntil == 0 || block.timestamp <= key.validUntil)) {
                count++;
            }
        }
        
        // Collect active keys
        activeKeys = new MeteorKey[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < allKeyIds.length; i++) {
            MeteorKey storage key = keys[owner][allKeyIds[i]];
            if (!key.revoked && (key.validUntil == 0 || block.timestamp <= key.validUntil)) {
                activeKeys[idx++] = key;
            }
        }
        
        return activeKeys;
    }
    
    /**
     * @notice Get the latest active key of a specific type for an address
     * @param owner Address to query
     * @param keyType Key type to find
     * @return key The latest active key (reverts if none found)
     */
    function getLatestKey(
        address owner,
        KeyType keyType
    ) external view returns (MeteorKey memory key) {
        bytes32[] storage allKeyIds = keyIdsByOwner[owner];
        
        // Iterate backwards to find latest
        for (uint256 i = allKeyIds.length; i > 0; i--) {
            MeteorKey storage candidate = keys[owner][allKeyIds[i - 1]];
            if (
                candidate.keyType == keyType &&
                !candidate.revoked &&
                (candidate.validUntil == 0 || block.timestamp <= candidate.validUntil)
            ) {
                return candidate;
            }
        }
        
        revert KeyNotFound(bytes32(0));
    }
    
    // =========================================================================
    // Batch Operations
    // =========================================================================
    
    /**
     * @notice Batch check key validity
     * @param keyIds Array of key IDs to check
     * @return validities Array of validity flags
     */
    function batchIsKeyValid(
        bytes32[] calldata keyIds
    ) external view returns (bool[] memory validities) {
        validities = new bool[](keyIds.length);
        for (uint256 i = 0; i < keyIds.length; i++) {
            validities[i] = this.isKeyValid(keyIds[i]);
        }
        return validities;
    }
    
    /**
     * @notice Batch get pk_blobs
     * @param keyIds Array of key IDs
     * @return pkBlobs Array of pk_blobs (empty bytes for non-existent keys)
     */
    function batchGetPkBlob(
        bytes32[] calldata keyIds
    ) external view returns (bytes[] memory pkBlobs) {
        pkBlobs = new bytes[](keyIds.length);
        for (uint256 i = 0; i < keyIds.length; i++) {
            address owner = keyOwner[keyIds[i]];
            if (owner != address(0)) {
                MeteorKey storage key = keys[owner][keyIds[i]];
                pkBlobs[i] = abi.encodePacked(key.pkSeed, key.bHash);
            }
        }
        return pkBlobs;
    }
}
