// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {TestMailbox} from "../../contracts/test/TestMailbox.sol";
import {CheckpointLib} from "../../contracts/libs/CheckpointLib.sol";
import {TypeCasts} from "../../contracts/libs/TypeCasts.sol";
import {Message} from "../../contracts/libs/Message.sol";
import {OptimisticIsm} from "../../contracts/isms/optimistic/OptmisticIsm.sol";

contract OptimisticTest is Test {
    uint32 constant ORIGIN = 11;
    OptimisticIsm ism;
    TestMailbox mailbox;

    function setUp() public {
        mailbox = new TestMailbox(ORIGIN);
        ism = new OptimisticIsm(15);
    }

    function getMessage(
        uint32 destination,
        bytes32 recipient,
        bytes calldata body
    ) internal returns (bytes memory) {
        uint8 version = mailbox.VERSION();
        uint32 origin = mailbox.localDomain();
        bytes32 sender = TypeCasts.addressToBytes32(address(this));
        uint32 nonce = mailbox.count();
        mailbox.dispatch(destination, recipient, body);
        bytes memory message = Message.formatMessage(
            version,
            nonce,
            origin,
            sender,
            destination,
            recipient,
            body
        );
        return message;
    }

    function getMetadata(uint32 checkpointIndex)
        private
        returns (bytes memory)
    {
        uint32 domain = mailbox.localDomain();
        bytes32 mailboxAsBytes32 = TypeCasts.addressToBytes32(address(mailbox));
        bytes32 checkpointRoot = mailbox.root();
        // uint32 checkpointIndex = uint32(mailbox.count() - 1);
        bytes memory metadata = abi.encodePacked(
            checkpointRoot,
            checkpointIndex,
            mailboxAsBytes32,
            mailbox.proof(checkpointIndex)
        );
        bytes32 digest = CheckpointLib.digest(
            domain,
            mailboxAsBytes32,
            checkpointRoot,
            checkpointIndex
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, digest);
        metadata = abi.encodePacked(metadata, r, s, v);
        return metadata;
    }

    function testVerify(
        uint32 destination,
        bytes32 recipient,
        bytes calldata body
    ) public {
        // vm.assume(0 < m && m <= n && n < 10);
        bytes memory message = getMessage(destination, recipient, body);

        address someUser = vm.addr(1);
        // vm.startPrank(someUser);
        // emit log_address(someUser);

        // ism.publishRoot(mailbox.root());
        // vm.stopPrank();
        skip(40);
        // ism.verify(metadata, message);
        bytes memory message1 = getMessage(destination, recipient, body);
        bytes memory metadata1 = getMetadata(1);
        // bytes memory metadata = getMetadata(0);

        vm.startPrank(someUser);
        emit log_address(someUser);

        ism.publishRoot(mailbox.root());
        vm.stopPrank();
        skip(40);
        ism.verify(metadata1, message1);
        // ism.verify(metadata, message);
    }
}
