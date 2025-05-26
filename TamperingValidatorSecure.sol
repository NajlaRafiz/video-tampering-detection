// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidatorSecure {
    struct VideoRecord {
        address uploader;
        string originalHash;
        bool isVerified;
        uint256 timestamp;
        bytes32 lastVerificationHash;
    }

    mapping(string => VideoRecord) public videos;

    event VideoStored(string indexed videoId, address indexed uploader, string hash);
    event VideoVerified(string indexed videoId, bool verified, address verifier, bytes32 signedHash, uint256 timestamp);

    modifier onlyUploader(string memory videoId) {
        require(videos[videoId].uploader == msg.sender, "Unauthorized: Not uploader");
        _;
    }

    function storeOriginal(string memory videoId, string memory hash) public {
        require(videos[videoId].uploader == address(0), "Video already exists");
        videos[videoId] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            isVerified: true,
            timestamp: block.timestamp,
            lastVerificationHash: 0x0
        });
        emit VideoStored(videoId, msg.sender, hash);
    }

    function verifyWithSignature(
        string memory videoId,
        string memory newHash,
        bytes memory signature
    ) public onlyUploader(videoId) returns (bool) {
        VideoRecord storage video = videos[videoId];

        bytes32 messageHash = getEthSignedMessageHash(keccak256(abi.encodePacked(videoId, newHash)));
        address signer = recoverSigner(messageHash, signature);

        require(signer == video.uploader, "Signature invalid or not from uploader");
        require(keccak256(bytes(newHash)) != video.lastVerificationHash, "Duplicate check");

        bool verified = (keccak256(bytes(video.originalHash)) == keccak256(bytes(newHash)));
        video.lastVerificationHash = keccak256(bytes(newHash));
        video.isVerified = verified;
        video.timestamp = block.timestamp;

        emit VideoVerified(videoId, verified, signer, video.lastVerificationHash, block.timestamp);
        return verified;
    }

    function getVerification(string memory videoId) public view returns (
        address uploader,
        string memory originalHash,
        bool isVerified,
        uint256 timestamp
    ) {
        VideoRecord memory video = videos[videoId];
        return (video.uploader, video.originalHash, video.isVerified, video.timestamp);
    }

    // ECDSA signature helpers
    function getEthSignedMessageHash(bytes32 _msgHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _msgHash));
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
