// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidatorSecure {
    struct VideoRecord {
        address uploader;
        string originalHash;
        string lastCheckedHash;
        bool isVerified;
        uint256 timestamp;
    }

    mapping(string => VideoRecord) public videos;

    // 🔐 Only the uploader can modify their own video's data
    modifier onlyUploader(string memory videoId) {
        require(msg.sender == videos[videoId].uploader, "Unauthorized: Not the uploader");
        _;
    }

    // ✅ Store original hash and set uploader
    function storeOriginal(string memory videoId, string memory hash) public {
        require(videos[videoId].uploader == address(0), "Video ID already exists");
        videos[videoId] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            lastCheckedHash: "",
            isVerified: true,
            timestamp: block.timestamp
        });
    }

    // 🔒 Only the original uploader can verify the video
    function verify(string memory videoId, string memory newHash) public onlyUploader(videoId) returns (bool) {
        VideoRecord storage video = videos[videoId];
        bool verified = (keccak256(bytes(video.originalHash)) == keccak256(bytes(newHash)));
        video.lastCheckedHash = newHash;
        video.isVerified = verified;
        video.timestamp = block.timestamp;
        return verified;
    }

    // 🧾 View result
    function getVerification(string memory videoId) public view returns (
        string memory originalHash,
        string memory lastCheckedHash,
        bool isVerified,
        uint256 timestamp,
        address uploader
    ) {
        VideoRecord memory video = videos[videoId];
        return (video.originalHash, video.lastCheckedHash, video.isVerified, video.timestamp, video.uploader);
    }
}
