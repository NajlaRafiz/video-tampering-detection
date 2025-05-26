// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TamperingValidatorSigned {
    struct VideoRecord {
        address uploader;
        string originalHash;
        bool isVerified;
        uint256 timestamp;
    }

    mapping(string => VideoRecord) public videos;

    event HashStored(string videoId, address uploader, string hash);
    event VerificationChecked(string videoId, bool result);

    // Upload original hash
    function storeOriginal(string memory videoId, string memory hash) public {
        require(videos[videoId].uploader == address(0), "Video ID already used.");
        videos[videoId] = VideoRecord({
            uploader: msg.sender,
            originalHash: hash,
            isVerified: true,
            timestamp: block.timestamp
        });
        emit HashStored(videoId, msg.sender, hash);
    }

    // Verify with signature (tamper protection)
    function verifyWithSignature(
        string memory videoId,
        string memory newHash,
        bytes memory signature
    ) public view returns (bool) {
        VideoRecord memory video = videos[videoId];
        require(video.uploader != address(0), "Video not found");

        bytes32 messageHash = getEthSignedMessageHash(keccak256(abi.encodePacked(videoId, newHash)));
        address signer = recoverSigner(messageHash, signature);

        bool valid = signer == video.uploader;
        return valid;
    }

    // ============ ECDSA Internal =============

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
