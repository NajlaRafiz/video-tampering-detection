// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidator {
    struct VideoRecord {
        string originalHash;
        string lastCheckedHash;
        bool isVerified;
        uint256 timestamp;
    }

    mapping(string => VideoRecord) public videos;

    // Store original hash
    function storeOriginal(string memory videoId, string memory hash) public {
        videos[videoId] = VideoRecord(hash, "", true, block.timestamp);
    }

    // Verify if new hash matches stored one
    function verify(string memory videoId, string memory newHash) public returns (bool) {
        VideoRecord storage video = videos[videoId];
        bool verified = (keccak256(bytes(video.originalHash)) == keccak256(bytes(newHash)));
        video.lastCheckedHash = newHash;
        video.isVerified = verified;
        video.timestamp = block.timestamp;
        return verified;
    }

    // Get verification result
    function getVerification(string memory videoId) public view returns (string memory, string memory, bool, uint256) {
        VideoRecord memory video = videos[videoId];
        return (video.originalHash, video.lastCheckedHash, video.isVerified, video.timestamp);
    }
}
