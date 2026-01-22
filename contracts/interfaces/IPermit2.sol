// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPermit2
 * @notice Permit2 AllowanceTransfer interface (subset of functions)
 * @dev Uniswap Permit2: 0x000000000022D473030F116dDEE9F6B43aC78BA3 (same address on all EVM chains)
 */
interface IPermit2 {
    // ============================================
    // Structs
    // ============================================

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct AllowanceTransferDetails {
        address from;
        address to;
        uint160 amount;
        address token;
    }

    // ============================================
    // Functions
    // ============================================

    /// @notice Set allowance (user signs -> server executes TX)
    function permit(
        address owner,
        PermitSingle calldata permitSingle,
        bytes calldata signature
    ) external;

    /// @notice Single transfer (deducts allowance)
    function transferFrom(
        address from,
        address to,
        uint160 amount,
        address token
    ) external;

    /// @notice Batch transfer (multiple users)
    function transferFrom(
        AllowanceTransferDetails[] calldata transferDetails
    ) external;

    /// @notice Query allowance
    function allowance(
        address user,
        address token,
        address spender
    ) external view returns (uint160 amount, uint48 expiration, uint48 nonce);
}
