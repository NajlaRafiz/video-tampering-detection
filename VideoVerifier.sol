// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VideoVerifier {
    struct VideoRecord {
        address uploader;
        string originalHash;
        bool isVerified;
        uint256 timestamp;
    }

    mapping(string => VideoRecord) private videoRecords;

    event VideoStored(string videoId, address uploader, string hash);
    event VideoVerified(string videoId, bool verified);

    // ✅ Store original hash of video
    function storeOriginal(string memory videoId, string memory hash) public {
        require(bytes(videoRecords[videoId].originalHash).length == 0, "Video ID already used");
        videoRecords[videoId] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            isVerified: false,
            timestamp: block.timestamp
        });
        emit VideoStored(videoId, msg.sender, hash);
    }

    // ✅ Verifies video tampering using MetaMask signature
    function verifyWithSignature(
        string memory videoId,
        string memory newHash,
        bytes memory signature
    ) public returns (bool) {
        require(signature.length == 65, "Invalid signature length");
        require(bytes(videoRecords[videoId].originalHash).length != 0, "Video not found");

        // ✅ Reconstruct the exact signed message (must match frontend)
        bytes32 message = keccak256(abi.encodePacked("VideoID:", videoId, "|Hash:", newHash));
        address signer = recoverSigner(message, signature);

        require(signer != address(0), "Invalid signer");
        require(signer == videoRecords[videoId].uploader, "Signature does not match uploader");

        bool verified = keccak256(bytes(videoRecords[videoId].originalHash)) == keccak256(bytes(newHash));
        videoRecords[videoId].isVerified = verified;

        emit VideoVerified(videoId, verified);
        return verified;
    }

    // ✅ Retrieve verification record
    function getVerification(string memory videoId) public view returns (
        address uploader,
        string memory originalHash,
        bool isVerified,
        uint256 timestamp
    ) {
        VideoRecord memory record = videoRecords[videoId];
        return (record.uploader, record.originalHash, record.isVerified, record.timestamp);
    }

    // ✅ Helper to recover signer from signature
    function recoverSigner(bytes32 message, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Signature length must be 65 bytes");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Inline assembly to split signature
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Ethereum Signed Message prefix
        bytes32 prefixedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );

        return ecrecover(prefixedMessage, v, r, s);
    }
}