// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VideoIntegrity {
    mapping(string => string) public videoHashes;

    function storeHash(string memory id, string memory hash) public {
        videoHashes[id] = hash;
    }

    function getHash(string memory id) public view returns (string memory) {
        return videoHashes[id];
    }

    function verifyHash(string memory id, string memory hash) public view returns (bool) {
        return keccak256(bytes(videoHashes[id])) == keccak256(bytes(hash));
    }
}
