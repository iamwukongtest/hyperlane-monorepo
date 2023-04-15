// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IMultisigIsm} from "../../interfaces/isms/IMultisigIsm.sol";
import {Message} from "../../libs/Message.sol";
import {LegacyMultisigIsmMetadata} from "../../libs/isms/LegacyMultisigIsmMetadata.sol";
import {MultisigIsmMetadata} from "../../libs/isms/MultisigIsmMetadata.sol";
import {CheckpointLib} from "../../libs/CheckpointLib.sol";
import {MerkleLib} from "../../libs/Merkle.sol";
import {MetaProxy} from "../../libs/MetaProxy.sol";

/**
 * @title MultisigIsm
 * @notice Manages per-domain m-of-n Validator sets that are used to verify
 * interchain messages.
 */
contract OptimisticIsm is IMultisigIsm {
    // ============ Constants ============
    event Validator(address _validator);

    // solhint-disable-next-line const-name-snakecase
    uint8 public constant moduleType =
        uint8(IInterchainSecurityModule.Types.MULTISIG);

    struct RootInfo {
        bool published;
        uint256 startingTime;
    }

    mapping(address => mapping(bytes32 => RootInfo)) validatorRootPublished;
    bool ismShutDown;
    uint256 window;

    constructor(uint256 _window) {
        window = _window;
    }

    // ============ Virtual Functions ============
    // ======= OVERRIDE THESE TO IMPLEMENT =======

    function validatorsAndThreshold(bytes calldata)
        public
        view
        returns (address[] memory, uint8)
    {
        return abi.decode(MetaProxy.metadata(), (address[], uint8));
    }

    // ============ Public Functions ============

    /**
     * @notice Requires that m-of-n validators verify a merkle root,
     * and verifies a merkle proof of `_message` against that root.
     * @param _metadata ABI encoded module metadata (see MultisigIsmMetadata.sol)
     * @param _message Formatted Hyperlane message (see Message.sol).
     */
    function verify(bytes calldata _metadata, bytes calldata _message)
        public
        returns (bool)
    {
        require(!ismShutDown, "System shut down");
        // address validator = LegacyMultisigIsmMetadata.validatorAt(_metadata, 0);
        address validator = recoverValidatorSignature(_metadata, _message);
        emit Validator(validator);
        require(
            validatorRootPublished[validator][
                MultisigIsmMetadata.root(_metadata)
            ].published,
            "Invalid root or root has not been published"
        );
        require(
            block.timestamp -
                validatorRootPublished[validator][
                    MultisigIsmMetadata.root(_metadata)
                ].startingTime >=
                window,
            "The time window for the root has not passed"
        );
        require(_verifyMerkleProof(_metadata, _message), "!merkle");
        return true;
    }

    function publishRoot(bytes32 root) external {
        require(!validatorRootPublished[msg.sender][root].published);
        validatorRootPublished[msg.sender][root].published = true;
        validatorRootPublished[msg.sender][root].startingTime = block.timestamp;
        emit Validator(msg.sender);
    }

    function challengeRoot(address validator, bytes32 root) external {
        require(
            validatorRootPublished[validator][root].published,
            "Root not published yet"
        );
        require(
            validatorRootPublished[validator][root].startingTime + window >
                block.timestamp,
            "Window for reporting is over"
        );
        ismShutDown = true;
    }

    // ============ Internal Functions ============

    /**
     * @notice Verifies the merkle proof of `_message` against the provided
     * checkpoint.
     * @param _metadata ABI encoded module metadata (see MultisigIsmMetadata.sol)
     * @param _message Formatted Hyperlane message (see Message.sol).
     */
    function _verifyMerkleProof(
        bytes calldata _metadata,
        bytes calldata _message
    ) internal pure returns (bool) {
        // calculate the expected root based on the proof
        bytes32 _calculatedRoot = MerkleLib.branchRoot(
            Message.id(_message),
            MultisigIsmMetadata.proof(_metadata),
            Message.nonce(_message)
        );
        return _calculatedRoot == MultisigIsmMetadata.root(_metadata);
    }

    /**
     * @notice Verifies that a quorum of the origin domain's validators signed
     * the provided checkpoint.
     * @param _metadata ABI encoded module metadata (see MultisigIsmMetadata.sol)
     * @param _message Formatted Hyperlane message (see Message.sol).
     */
    function recoverValidatorSignature(
        bytes calldata _metadata,
        bytes calldata _message
    ) internal view returns (address) {
        bytes32 _digest = CheckpointLib.digest(
            Message.origin(_message),
            MultisigIsmMetadata.originMailbox(_metadata),
            MultisigIsmMetadata.root(_metadata),
            MultisigIsmMetadata.index(_metadata)
        );
        address _signer = ECDSA.recover(
            _digest,
            MultisigIsmMetadata.signatureAt(_metadata, 0)
        );
        return _signer;
    }
}
