// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IPQReleaseLogKillTest {
    function registerProject(string calldata name, bytes calldata vk, bytes calldata popSig) external;

    function projectKey(address owner, string calldata name) external pure returns (bytes32);

    function publish(bytes32 projectKey, uint64 seq, bytes32 manifestHash, string calldata uri, bytes calldata sig)
        external;
}

/// @notice Stateless helper used only as state-override bytecode by test/killtest.sh.
contract KillTestHarness {
    string internal constant PROJECT_NAME = "paylink-killtest";

    function run(
        address registry,
        bytes calldata vk,
        bytes calldata popSig,
        uint64 seq,
        bytes32 manifestHash,
        string calldata uri,
        bytes calldata sig
    ) external returns (uint256 publishGas) {
        bytes32 key = IPQReleaseLogKillTest(registry).projectKey(address(this), PROJECT_NAME);
        IPQReleaseLogKillTest(registry).registerProject(PROJECT_NAME, vk, popSig);
        uint256 beforeGas = gasleft();
        IPQReleaseLogKillTest(registry).publish(key, seq, manifestHash, uri, sig);
        publishGas = beforeGas - gasleft();
    }
}
