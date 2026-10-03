// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQReleaseLog} from "../src/PQReleaseLog.sol";

contract TablePQMock {
    mapping(bytes32 => bool) internal allowed;

    function verifySlhDsaSha2128s(bytes calldata vk, bytes calldata message, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return allowed[keccak256(abi.encode(vk, message, sig))];
    }
}

contract FailingPQMock {
    fallback() external {
        revert("mock failure");
    }
}

contract MalformedPQMock {
    fallback() external {
        assembly {
            mstore(0, 2)
            return(0, 32)
        }
    }
}

contract LongPQMock {
    fallback() external {
        assembly {
            mstore(0, 1)
            mstore(32, 0)
            return(0, 64)
        }
    }
}

contract PQReleaseLogTest is Test {
    address internal constant PRECOMPILE = 0x1800000000000000000000000000000000000004;
    string internal constant NAME = "paylink";
    bytes internal constant VK = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    bytes internal constant OTHER_VK = hex"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    address internal owner = makeAddr("owner");
    address internal stranger = makeAddr("stranger");
    PQReleaseLog internal registry;

    function _key(PQReleaseLog target, address who, string memory name) internal pure returns (bytes32) {
        return target.projectKey(who, name);
    }

    function setUp() public {
        vm.etch(PRECOMPILE, address(new TablePQMock()).code);
        registry = new PQReleaseLog();
    }

    function _allow(bytes memory vk, bytes memory message, bytes memory sig) internal {
        bytes32 key = keccak256(abi.encode(vk, message, sig));
        bytes32 slot = keccak256(abi.encode(key, uint256(0)));
        vm.store(PRECOMPILE, slot, bytes32(uint256(1)));
    }

    function _registerMessage(PQReleaseLog target, bytes32 id, address who, uint256 chain)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked("PQRL-REGISTER-v1", chain, address(target), id, who, VK);
    }

    function _publishMessage(
        PQReleaseLog target,
        bytes32 id,
        uint64 seq,
        bytes32 hash,
        string memory uri,
        uint256 chain
    ) internal pure returns (bytes memory) {
        return abi.encodePacked("PQRL-PUBLISH-v1", chain, address(target), id, seq, hash, keccak256(bytes(uri)));
    }

    function _register(PQReleaseLog target) internal {
        bytes32 key = _key(target, owner, NAME);
        bytes memory sig = hex"a1";
        _allow(VK, _registerMessage(target, key, owner, block.chainid), sig);
        vm.prank(owner);
        target.registerProject(NAME, VK, sig);
    }

    function _publish(PQReleaseLog target, uint64 seq, bytes32 hash, string memory uri) internal {
        bytes memory sig = abi.encodePacked(bytes1(0xb0), seq);
        bytes32 key = _key(target, owner, NAME);
        _allow(VK, _publishMessage(target, key, seq, hash, uri, block.chainid), sig);
        vm.prank(owner);
        target.publish(key, seq, hash, uri, sig);
    }

    function testRegistrationAndViews() public {
        _register(registry);
        bytes32 key = _key(registry, owner, NAME);
        (address gotOwner, bytes memory gotVk, uint64 latestSeq) = registry.project(key);
        assertEq(gotOwner, owner);
        assertEq(gotVk, VK);
        assertEq(latestSeq, 0);
        assertEq(registry.ownerVkHash(owner), keccak256(VK));
        assertEq(registry.registrationBlockFor(key), block.number);
    }

    function testOwnerKeyBindingAllowsSameKeyAndRejectsStolenEoaDifferentKey() public {
        _register(registry);
        string memory secondName = "paylink-v2";
        bytes32 secondKey = _key(registry, owner, secondName);
        bytes memory sameKeyPop = hex"0202";
        _allow(VK, _registerMessage(registry, secondKey, owner, block.chainid), sameKeyPop);
        vm.prank(owner);
        registry.registerProject(secondName, VK, sameKeyPop);
        (address gotOwner, bytes memory gotVk,) = registry.project(secondKey);
        assertEq(gotOwner, owner);
        assertEq(gotVk, VK);

        string memory stolenName = "attacker-name";
        bytes32 stolenKey = _key(registry, owner, stolenName);
        bytes memory attackerPop = hex"0303";
        bytes memory attackerMessage =
            abi.encodePacked("PQRL-REGISTER-v1", block.chainid, address(registry), stolenKey, owner, OTHER_VK);
        _allow(OTHER_VK, attackerMessage, attackerPop);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQReleaseLog.OwnerVerificationKeyMismatch.selector, keccak256(VK), keccak256(OTHER_VK)
            )
        );
        vm.prank(owner);
        registry.registerProject(stolenName, OTHER_VK, attackerPop);
    }

    function testRegistrationOnlyOnce() public {
        _register(registry);
        bytes32 key = _key(registry, owner, NAME);
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.ProjectAlreadyRegistered.selector, key));
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"a1");
    }

    function testBadProofOfPossession() public {
        vm.expectRevert(PQReleaseLog.InvalidProofOfPossession.selector);
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"bad0");
    }

    function testRejectsWrongVerificationKeyLength() public {
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.InvalidVerificationKeyLength.selector, 1));
        vm.prank(owner);
        registry.registerProject(NAME, hex"00", hex"a1");
    }

    function testPublishAndViewsAndVerifyFor() public {
        _register(registry);
        bytes32 hash = sha256("manifest");
        string memory uri = "ipfs://release-1";
        vm.roll(12345);
        vm.warp(1770000000);
        _publish(registry, 1, hash, uri);

        bytes32 key = _key(registry, owner, NAME);
        (uint64 latestSeq, PQReleaseLog.Release memory latestRelease) = registry.latest(key);
        assertEq(latestSeq, 1);
        assertEq(latestRelease.manifestHash, hash);
        assertEq(latestRelease.uri, uri);
        assertEq(latestRelease.blockNumber, 12345);
        assertEq(latestRelease.timestamp, 1770000000);
        PQReleaseLog.Release memory bySeq = registry.release(owner, NAME, 1);
        assertEq(bySeq.manifestHash, hash);
        (bool valid, uint64 foundSeq) = registry.verifyFor(key, hash);
        assertTrue(valid);
        assertEq(foundSeq, 1);
        (valid, foundSeq) = registry.verifyFor(owner, NAME, sha256("other"));
        assertFalse(valid);
        assertEq(foundSeq, 0);
        assertEq(registry.latestSeqFor(key), 1);
        assertEq(registry.latestSeqFor(owner, NAME), 1);
    }

    function testVerifyForKeepsFirstSequenceAndCallerCanCheckCurrency() public {
        _register(registry);
        bytes32 hash = sha256("manifest-a");
        _publish(registry, 1, hash, "a");
        _publish(registry, 2, sha256("manifest-b"), "b");
        _publish(registry, 3, hash, "a-again");
        bytes32 key = _key(registry, owner, NAME);
        (bool valid, uint64 firstSeq) = registry.verifyFor(key, hash);
        assertTrue(valid);
        assertEq(firstSeq, 1);
        assertEq(registry.latestSeqFor(owner, NAME), 3);
        assertTrue(firstSeq != registry.latestSeqFor(key));
    }

    function testPublishedEventCarriesSignature() public {
        _register(registry);
        bytes32 key = _key(registry, owner, NAME);
        bytes32 hash = sha256("manifest");
        string memory uri = "https://example.test/manifest.json";
        bytes memory sig = hex"c001";
        _allow(VK, _publishMessage(registry, key, 1, hash, uri, block.chainid), sig);
        vm.expectEmit(true, true, true, true, address(registry));
        emit PQReleaseLog.Published(key, 1, hash, uri, uint64(block.number), uint64(block.timestamp), sig);
        vm.prank(owner);
        registry.publish(key, 1, hash, uri, sig);
    }

    function testPublishByNonOwner() public {
        _register(registry);
        bytes32 hash = sha256("m");
        bytes32 key = _key(registry, owner, NAME);
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.NotProjectOwner.selector, stranger));
        vm.prank(stranger);
        registry.publish(key, 1, hash, "uri", hex"01");
    }

    function testWrongSequenceReplayAndGap() public {
        _register(registry);
        _publish(registry, 1, sha256("one"), "one");
        bytes32 key = _key(registry, owner, NAME);
        bytes32 againHash = sha256("again");
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.WrongSequence.selector, 2, 1));
        vm.prank(owner);
        registry.publish(key, 1, againHash, "again", hex"01");
        bytes32 gapHash = sha256("gap");
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.WrongSequence.selector, 2, 3));
        vm.prank(owner);
        registry.publish(key, 3, gapHash, "gap", hex"03");
    }

    function testTamperedManifestUriSeqProjectAndChain() public {
        _register(registry);
        bytes32 hash = sha256("right");
        bytes32 key = _key(registry, owner, NAME);
        string memory uri = "right-uri";
        bytes memory sig = hex"cafe";
        _allow(VK, _publishMessage(registry, key, 1, hash, uri, block.chainid), sig);
        bytes32 wrongHash = sha256("wrong");

        vm.startPrank(owner);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        registry.publish(key, 1, wrongHash, uri, sig);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        registry.publish(key, 1, hash, "wrong-uri", sig);
        vm.stopPrank();

        // A valid seq-1 signature cannot authenticate the otherwise expected seq 2.
        vm.prank(owner);
        registry.publish(key, 1, hash, uri, sig);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        vm.prank(owner);
        registry.publish(key, 2, hash, uri, sig);

        bytes32 wrongProject = keccak256("wrong-project");
        bytes memory wrongProjectSig = hex"0303";
        _allow(VK, _publishMessage(registry, wrongProject, 2, hash, uri, block.chainid), wrongProjectSig);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        vm.prank(owner);
        registry.publish(key, 2, hash, uri, wrongProjectSig);

        bytes memory wrongChainSig = hex"0404";
        _allow(VK, _publishMessage(registry, key, 2, hash, uri, block.chainid + 1), wrongChainSig);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        vm.prank(owner);
        registry.publish(key, 2, hash, uri, wrongChainSig);
    }

    function testSignedSequenceCannotSkip() public {
        string memory secondName = "second";
        bytes32 second = _key(registry, owner, secondName);
        bytes memory pop = hex"02";
        _allow(VK, _registerMessage(registry, second, owner, block.chainid), pop);
        vm.prank(owner);
        registry.registerProject(secondName, VK, pop);
        bytes32 hash = sha256("right");
        bytes memory seqSig = hex"0202";
        _allow(VK, _publishMessage(registry, second, 2, hash, "right-uri", block.chainid), seqSig);
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.WrongSequence.selector, 1, 2));
        vm.prank(owner);
        registry.publish(second, 2, hash, "right-uri", seqSig);
    }

    function testCrossRegistryReplayFails() public {
        _register(registry);
        PQReleaseLog second = new PQReleaseLog();
        bytes memory firstPop = hex"7777";
        bytes32 key = _key(registry, owner, NAME);
        bytes32 secondKey = _key(second, owner, NAME);
        _allow(VK, _registerMessage(registry, key, owner, block.chainid), firstPop);
        vm.expectRevert(PQReleaseLog.InvalidProofOfPossession.selector);
        vm.prank(owner);
        second.registerProject(NAME, VK, firstPop);

        bytes memory secondPop = hex"8888";
        _allow(VK, _registerMessage(second, secondKey, owner, block.chainid), secondPop);
        vm.prank(owner);
        second.registerProject(NAME, VK, secondPop);

        bytes32 hash = sha256("release");
        bytes memory firstRegistrySig = hex"9999";
        _allow(VK, _publishMessage(registry, key, 1, hash, "uri", block.chainid), firstRegistrySig);
        vm.expectRevert(PQReleaseLog.InvalidReleaseSignature.selector);
        vm.prank(owner);
        second.publish(secondKey, 1, hash, "uri", firstRegistrySig);
    }

    function testPrecompileFailureAndMalformedPaths() public {
        vm.etch(PRECOMPILE, address(new FailingPQMock()).code);
        vm.expectRevert(PQReleaseLog.PrecompileCallFailed.selector);
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"01");

        vm.etch(PRECOMPILE, hex"");
        vm.expectRevert(PQReleaseLog.PrecompileMalformedResponse.selector);
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"01");

        vm.etch(PRECOMPILE, address(new LongPQMock()).code);
        vm.expectRevert(PQReleaseLog.PrecompileMalformedResponse.selector);
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"01");

        vm.etch(PRECOMPILE, address(new MalformedPQMock()).code);
        vm.expectRevert(PQReleaseLog.PrecompileMalformedResponse.selector);
        vm.prank(owner);
        registry.registerProject(NAME, VK, hex"01");
    }

    function testUnregisteredPublishFails() public {
        bytes32 hash = sha256("x");
        bytes32 key = _key(registry, owner, NAME);
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.ProjectNotRegistered.selector, key));
        registry.publish(key, 1, hash, "uri", hex"01");
    }

    function testSameNameIsNamespacedAndCannotBeSquatted() public {
        _register(registry);
        bytes32 ownerKey = _key(registry, owner, NAME);
        bytes32 strangerKey = _key(registry, stranger, NAME);
        assertTrue(ownerKey != strangerKey);

        bytes memory pop = hex"55";
        _allow(VK, _registerMessage(registry, strangerKey, stranger, block.chainid), pop);
        vm.prank(stranger);
        registry.registerProject(NAME, VK, pop);

        (address firstOwner,,) = registry.project(ownerKey);
        (address secondOwner,,) = registry.project(strangerKey);
        assertEq(firstOwner, owner);
        assertEq(secondOwner, stranger);
        bytes32 squatHash = sha256("squat");
        vm.expectRevert(abi.encodeWithSelector(PQReleaseLog.NotProjectOwner.selector, stranger));
        vm.prank(stranger);
        registry.publish(ownerKey, 1, squatHash, "uri", hex"01");
    }

    function testNameValidation() public {
        vm.startPrank(owner);
        vm.expectRevert(PQReleaseLog.InvalidProjectName.selector);
        registry.registerProject("", VK, hex"01");
        vm.expectRevert(PQReleaseLog.InvalidProjectName.selector);
        registry.registerProject("Not-valid", VK, hex"01");
        vm.expectRevert(PQReleaseLog.InvalidProjectName.selector);
        registry.registerProject("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm", VK, hex"01");
        vm.stopPrank();
    }

    function testFixedMessageVector() public view {
        address fixedOwner = 0x3DF09eF258C7589508aD92b48896cE9763Df7231;
        address fixedRegistry = 0x0000000000000000000000000000000000001234;
        bytes32 key = registry.projectKey(fixedOwner, "paylink");
        assertEq(key, 0x07be0dc2cab94bbfd1037fe20159c1cc714ecdfe99449410b2eb87d62caeb89b);
        bytes memory encoded = abi.encodePacked(
            "PQRL-PUBLISH-v1",
            uint256(5042),
            fixedRegistry,
            key,
            uint64(7),
            bytes32(uint256(0x1234)),
            keccak256(bytes("https://example.test/m.json"))
        );
        assertEq(keccak256(encoded), 0x6c7278627adc0ea0972ecd05b3cfc35ad9041e8b7133a0b7c27904ce27e3dc10);
    }

    function testKeccakRateBoundaryVectors() public pure {
        assertEq(keccak256(new bytes(135)), 0x29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e);
        assertEq(keccak256(new bytes(136)), 0x3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9);
        assertEq(keccak256(new bytes(271)), 0x3bb611e98ca876adc01436a582979ecfd012389033aca7dbf76dcb424fe02a0c);
    }
}
