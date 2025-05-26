// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidatorFinal {
    struct VideoRecord {
        address uploader;
        string originalHash;
        bool isVerified;
        uint256 timestamp;
        bytes32 lastVerificationHash;
    }

    mapping(bytes32 => VideoRecord) private videoRecords;
    mapping(bytes32 => bool) private usedSignatures;

    event VideoStored(bytes32 indexed videoKey, address indexed uploader, string hash);
    event VideoVerified(bytes32 indexed videoKey, bool verified, address verifier, bytes32 signedHash, uint256 timestamp);

    function storeOriginal(string memory videoId, string memory hash) public {
        bytes32 videoKey = keccak256(abi.encodePacked(videoId));
        require(videoRecords[videoKey].uploader == address(0), "Video already exists");
        videoRecords[videoKey] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            isVerified: true,
            timestamp: block.timestamp,
            lastVerificationHash: 0x0
        });
        emit VideoStored(videoKey, msg.sender, hash);
    }

    function verifyWithSignature(string memory videoId, string memory newHash, bytes memory signature) public returns (bool) {
        bytes32 videoKey = keccak256(abi.encodePacked(videoId));
        VideoRecord storage video = videoRecords[videoKey];

        require(video.uploader == msg.sender, "Only uploader can verify");

        bytes32 msgHash = getEthSignedMessageHash(keccak256(abi.encodePacked(videoId, newHash)));
        require(!usedSignatures[msgHash], "Signature already used");

        address signer = recoverSigner(msgHash, signature);
        require(signer == video.uploader, "Invalid signature");

        bool verified = keccak256(bytes(video.originalHash)) == keccak256(bytes(newHash));
        video.lastVerificationHash = keccak256(bytes(newHash));
        video.isVerified = verified;
        video.timestamp = block.timestamp;

        usedSignatures[msgHash] = true;

        emit VideoVerified(videoKey, verified, signer, video.lastVerificationHash, block.timestamp);
        return verified;
    }

    function getVerification(string memory videoId) public view returns (
        address uploader,
        string memory originalHash,
        bool isVerified,
        uint256 timestamp
    ) {
        bytes32 videoKey = keccak256(abi.encodePacked(videoId));
        VideoRecord memory video = videoRecords[videoKey];
        return (video.uploader, video.originalHash, video.isVerified, video.timestamp);
    }

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
