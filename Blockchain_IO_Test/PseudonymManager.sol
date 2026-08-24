                               
pragma solidity ^0.8.0;

contract PseudonymManager {

    uint256 private constant FINGERPRINT_LENGTH = 128;

    struct PseudonymData {
        bytes18 pseudonym;
        bytes fingerprint;
        uint256 timestamp;
    }

    mapping(bytes18 => PseudonymData) public pseudonymRegistry;

    event PseudonymUpdated(
        bytes18 indexed pseudonym,
        uint256 timestamp
    );

    function updatePseudonym(
        bytes18 _newPseudonym,
        bytes calldata _fingerprint
    ) external {
        require(
            _fingerprint.length == FINGERPRINT_LENGTH,
            "Fingerprint must be 128 bytes"
        );

        pseudonymRegistry[_newPseudonym] = PseudonymData({
            pseudonym: _newPseudonym,
            fingerprint: _fingerprint,
            timestamp: block.timestamp
        });

        emit PseudonymUpdated(_newPseudonym, block.timestamp);
    }

    function getPseudonymData(bytes18 _pseudonym)
        external
        view
        returns (
            bytes18 pseudonym,
            bytes memory fingerprint,
            uint256 timestamp
        )
    {
        PseudonymData storage data =
            pseudonymRegistry[_pseudonym];

        return (
            data.pseudonym,
            data.fingerprint,
            data.timestamp
        );
    }
}