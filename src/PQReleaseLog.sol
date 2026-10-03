// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title PQReleaseLog
/// @notice Admin-free, append-only release commitments authenticated by an EOA
///         and Arc's experimental SLH-DSA-SHA2-128s precompile.
contract PQReleaseLog {
    address public constant SLH_DSA_SHA2_128S = 0x1800000000000000000000000000000000000004;

    bytes16 internal constant REGISTER_DOMAIN = "PQRL-REGISTER-v1";
    bytes15 internal constant PUBLISH_DOMAIN = "PQRL-PUBLISH-v1";

    struct ProjectData {
        address owner;
        bytes vk;
        uint64 latestSeq;
    }

    struct Release {
        bytes32 manifestHash;
        string uri;
        uint64 blockNumber;
        uint64 timestamp;
    }

    mapping(bytes32 => ProjectData) private _projects;
    mapping(bytes32 => mapping(uint64 => Release)) private _releases;
    mapping(bytes32 => mapping(bytes32 => uint64)) private _manifestSeq;
    /// @notice Keccak-256 fingerprint of the single SLH-DSA verification key bound to each owner.
    mapping(address => bytes32) public ownerVkHash;
    /// @notice Block in which each project was registered.
    mapping(bytes32 => uint64) public registrationBlockFor;

    event ProjectRegistered(bytes32 indexed projectKey, address indexed owner, string name, bytes vk);
    event Published(
        bytes32 indexed projectKey,
        uint64 indexed seq,
        bytes32 indexed manifestHash,
        string uri,
        uint64 blockNumber,
        uint64 timestamp,
        bytes sig
    );

    error ProjectAlreadyRegistered(bytes32 projectKey);
    error ProjectNotRegistered(bytes32 projectKey);
    error InvalidProjectName();
    error InvalidVerificationKeyLength(uint256 length);
    error InvalidProofOfPossession();
    error OwnerVerificationKeyMismatch(bytes32 expected, bytes32 supplied);
    error NotProjectOwner(address caller);
    error WrongSequence(uint64 expected, uint64 supplied);
    error SequenceExhausted();
    error InvalidReleaseSignature();
    error PrecompileCallFailed();
    error PrecompileMalformedResponse();

    function registerProject(string calldata name, bytes calldata vk, bytes calldata popSig) external {
        bytes32 key = projectKey(msg.sender, name);
        if (_projects[key].owner != address(0)) revert ProjectAlreadyRegistered(key);
        if (vk.length != 32) revert InvalidVerificationKeyLength(vk.length);

        bytes32 vkHash = keccak256(vk);
        bytes32 boundHash = ownerVkHash[msg.sender];
        if (boundHash != bytes32(0) && vkHash != boundHash) {
            revert OwnerVerificationKeyMismatch(boundHash, vkHash);
        }

        bytes memory message = abi.encodePacked(REGISTER_DOMAIN, block.chainid, address(this), key, msg.sender, vk);
        if (!_verify(vk, message, popSig)) revert InvalidProofOfPossession();

        if (boundHash == bytes32(0)) ownerVkHash[msg.sender] = vkHash;
        _projects[key] = ProjectData({owner: msg.sender, vk: vk, latestSeq: 0});
        // uint64 outlives any practical EVM block-height horizon.
        // forge-lint: disable-next-line(unsafe-typecast)
        registrationBlockFor[key] = uint64(block.number);
        // The preceding external operation is a STATICCALL to Arc's precompile.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ProjectRegistered(key, msg.sender, name, vk);
    }

    function publish(bytes32 key, uint64 seq, bytes32 manifestHash, string calldata uri, bytes calldata sig) external {
        ProjectData storage p = _projects[key];
        if (p.owner == address(0)) revert ProjectNotRegistered(key);
        if (msg.sender != p.owner) revert NotProjectOwner(msg.sender);
        if (p.latestSeq == type(uint64).max) revert SequenceExhausted();
        uint64 expected = p.latestSeq + 1;
        if (seq != expected) revert WrongSequence(expected, seq);

        bytes memory message = abi.encodePacked(
            PUBLISH_DOMAIN, block.chainid, address(this), key, seq, manifestHash, keccak256(bytes(uri))
        );
        if (!_verify(p.vk, message, sig)) revert InvalidReleaseSignature();

        // uint64 outlives any practical EVM block-height or timestamp horizon.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 storedBlock = uint64(block.number);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 storedTime = uint64(block.timestamp);
        _releases[key][seq] = Release(manifestHash, uri, storedBlock, storedTime);
        p.latestSeq = seq;
        // Sequence zero is the sentinel for "not published".
        if (_manifestSeq[key][manifestHash] == 0) {
            _manifestSeq[key][manifestHash] = seq;
        }
        // The preceding external operation is a STATICCALL to Arc's precompile.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Published(key, seq, manifestHash, uri, storedBlock, storedTime, sig);
    }

    function projectKey(address owner, string memory name) public pure returns (bytes32) {
        bytes memory raw = bytes(name);
        if (raw.length == 0 || raw.length > 64) revert InvalidProjectName();
        bool valid = true;
        for (uint256 i; i < raw.length; ++i) {
            bytes1 c = raw[i];
            if (!((c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2d)) {
                valid = false;
                break;
            }
        }
        if (!valid) revert InvalidProjectName();
        return keccak256(abi.encode(owner, name));
    }

    function latest(bytes32 key) public view returns (uint64 seq, Release memory data) {
        seq = _projects[key].latestSeq;
        data = _releases[key][seq];
    }

    function latest(address owner, string calldata name) external view returns (uint64 seq, Release memory data) {
        return latest(projectKey(owner, name));
    }

    function release(bytes32 key, uint64 seq) public view returns (Release memory) {
        return _releases[key][seq];
    }

    function release(address owner, string calldata name, uint64 seq) external view returns (Release memory) {
        return release(projectKey(owner, name), seq);
    }

    function project(bytes32 key) public view returns (address owner, bytes memory vk, uint64 latestSeq) {
        ProjectData storage p = _projects[key];
        return (p.owner, p.vk, p.latestSeq);
    }

    function project(address owner, string calldata name)
        external
        view
        returns (address projectOwner, bytes memory vk, uint64 latestSeq)
    {
        return project(projectKey(owner, name));
    }

    /// @notice Reports whether a manifest was ever published and its first sequence number.
    /// @dev This is stable historical identity, not a currency check. Compare `seq` with
    ///      `latestSeqFor(key)` (or `latest(key).seq`) to determine whether it is current.
    function verifyFor(bytes32 key, bytes32 manifestHash) public view returns (bool valid, uint64 seq) {
        seq = _manifestSeq[key][manifestHash];
        valid = seq != 0;
    }

    function verifyFor(address owner, string calldata name, bytes32 manifestHash)
        external
        view
        returns (bool valid, uint64 seq)
    {
        return verifyFor(projectKey(owner, name), manifestHash);
    }

    /// @notice Returns the latest published sequence for a project, or zero if unregistered/unpublished.
    function latestSeqFor(bytes32 key) public view returns (uint64) {
        return _projects[key].latestSeq;
    }

    /// @notice Returns the latest sequence for `owner` and `name`; compare it with `verifyFor`'s first seq.
    function latestSeqFor(address owner, string calldata name) external view returns (uint64) {
        return latestSeqFor(projectKey(owner, name));
    }

    function _verify(bytes memory vk, bytes memory message, bytes memory sig) internal view returns (bool valid) {
        (bool ok, bytes memory result) = SLH_DSA_SHA2_128S.staticcall(
            abi.encodeWithSignature("verifySlhDsaSha2128s(bytes,bytes,bytes)", vk, message, sig)
        );
        if (!ok) revert PrecompileCallFailed();
        if (result.length != 32) revert PrecompileMalformedResponse();
        uint256 word;
        assembly ("memory-safe") {
            word := mload(add(result, 0x20))
        }
        if (word > 1) revert PrecompileMalformedResponse();
        valid = word == 1;
    }
}
