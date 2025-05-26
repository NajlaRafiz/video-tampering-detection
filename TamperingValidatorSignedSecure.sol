// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidatorSignedSecure {
    struct VideoRecord {
        address uploader;
        string originalHash;
        bool isVerified;
        uint256 timestamp;
        bytes32 lastVerificationHash;
    }

    mapping(string => VideoRecord) public videos;
    mapping(bytes32 => bool) public usedSignatures;

    event HashStored(string videoId, address uploader, string hash);
    event VerificationChecked(string videoId, bool result);

    // ✅ Proper modifier
    modifier onlyUploader(string memory videoId) {
        require(videos[videoId].uploader == msg.sender, "Unauthorized: not uploader");
        _;
    }

    // ✅ Store original hash (only once per videoId)
    function storeOriginal(string memory videoId, string memory hash) public {
        require(videos[videoId].uploader == address(0), "Video already exists");
        videos[videoId] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            isVerified: true,
            timestamp: block.timestamp,
            lastVerificationHash: 0x0
        });
        emit HashStored(videoId, msg.sender, hash);
    }

    // ✅ Verify with signature (protected from replay + spoof)
    function verifyWithSignature(
        string memory videoId,
        string memory newHash,
        bytes memory signature
    ) public onlyUploader(videoId) returns (bool) {
        VideoRecord storage video = videos[videoId];

        // Construct message hash
        bytes32 messageHash = getEthSignedMessageHash(keccak256(abi.encodePacked(videoId, newHash)));

        require(!usedSignatures[messageHash], "Replay attack: signature already used");

        address signer = recoverSigner(messageHash, signature);
        require(signer == video.uploader, "Invalid signature");

        bool verified = keccak256(bytes(video.originalHash)) == keccak256(bytes(newHash));
        video.lastVerificationHash = keccak256(bytes(newHash));
        video.isVerified = verified;
        video.timestamp = block.timestamp;

        usedSignatures[messageHash] = true;

        emit VerificationChecked(videoId, verified);
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

    // ✅ ECDSA Signature Helpers
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
