// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPermit2} from "./interfaces/IPermit2.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title SettoGaslessRelay
 * @notice Gasless relay contract for ERC20 token transfers (Permit2 + EIP-2612 Permit)
 * @dev Features:
 *      - EIP-2612 Permit support (USDC - no initial approve TX needed)
 *      - Permit2 support (USDT and other tokens)
 *      - Multi-signer/relayer support
 *      - Emergency pause/unpause
 */
contract SettoGaslessRelay is Initializable, EIP712Upgradeable, ReentrancyGuardUpgradeable, MulticallUpgradeable, UUPSUpgradeable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ============================================
    // Constants
    // ============================================

    bytes32 public constant PAYMENT_TYPEHASH = keccak256(
        "Payment("
            "bytes32 paymentId,"
            "address user,"
            "address pool,"
            "address to,"
            "address token,"
            "uint256 amount,"
            "uint256 fee,"
            "uint256 deadline"
        ")"
    );

    // ============================================
    // State Variables
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IPermit2 public immutable permit2;
    address public owner;
    address public emergencyAdmin;
    mapping(address => bool) public relayers;
    mapping(address => bool) public serverSigners;
    bool public paused;

    address[] private _relayerList;
    address[] private _serverSignerList;

    // ============================================
    // Structs
    // ============================================

    struct Payment {
        bytes32 paymentId;
        address user;
        address pool;
        address token;
        uint256 amount;
        uint256 fee;
        uint256 deadline;
        address to;
        bytes serverSignature;
    }

    struct ERC20PermitSignature {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // ============================================
    // Events
    // ============================================

    event PaymentExecuted(
        bytes32 indexed paymentId,
        address indexed from,
        address indexed to,
        address pool,
        uint256 amount,
        uint256 feeAmount
    );

    event PaymentFailed(
        bytes32 indexed paymentId,
        address indexed user,
        uint256 amount,
        string reason
    );

    event BatchCompleted(uint256 totalCount, uint256 successCount);

    event ServerSignerAdded(address indexed signer);
    event ServerSignerRemoved(address indexed signer);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event EmergencyAdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // ============================================
    // Modifiers
    // ============================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyEmergencyAdmin() {
        require(msg.sender == emergencyAdmin, "Not emergency admin");
        _;
    }

    modifier onlyRelayer() {
        require(relayers[msg.sender], "Not relayer");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // ============================================
    // Constructor & Initializer
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address _permit2) {
        require(_permit2 != address(0), "Invalid permit2");
        permit2 = IPermit2(_permit2);
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _emergencyAdmin,
        address[] calldata _serverSigners,
        address[] calldata _relayers
    ) public initializer {
        require(_owner != address(0), "Invalid owner");
        require(_emergencyAdmin != address(0), "Invalid emergencyAdmin");
        require(_serverSigners.length > 0, "No serverSigners");
        require(_relayers.length > 0, "No relayers");
        require(_owner != address(this), "Owner cannot be this contract");
        require(_emergencyAdmin != address(this), "EmergencyAdmin cannot be this contract");

        __EIP712_init("SettoGaslessRelay", "1");
        __ReentrancyGuard_init();
        __Multicall_init();
        __UUPSUpgradeable_init();

        owner = _owner;
        emergencyAdmin = _emergencyAdmin;

        for (uint256 i = 0; i < _serverSigners.length; i++) {
            require(_serverSigners[i] != address(0), "Invalid serverSigner");
            require(!serverSigners[_serverSigners[i]], "Duplicate serverSigner");
            serverSigners[_serverSigners[i]] = true;
            _serverSignerList.push(_serverSigners[i]);
            emit ServerSignerAdded(_serverSigners[i]);
        }

        for (uint256 i = 0; i < _relayers.length; i++) {
            require(_relayers[i] != address(0), "Invalid relayer");
            require(!relayers[_relayers[i]], "Duplicate relayer");
            relayers[_relayers[i]] = true;
            _relayerList.push(_relayers[i]);
            emit RelayerAdded(_relayers[i]);
        }
    }

    // ============================================
    // UUPS Upgrade Authorization
    // ============================================

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ============================================
    // External Functions - Permit2
    // ============================================

    /**
     * @notice Set Permit2 allowance + batch payment processing (for first-time payments)
     * @param permitOwners Array of Permit2 signers (token owners)
     * @param permitSingles Array of Permit2 PermitSingle structs
     * @param permitSignatures Array of Permit2 signatures (empty bytes skips permit)
     * @param payments Array of payment info
     * @param feeWallet Address to receive fees
     */
    function batchPermitAndPay(
        address[] calldata permitOwners,
        IPermit2.PermitSingle[] calldata permitSingles,
        bytes[] calldata permitSignatures,
        Payment[] calldata payments,
        address feeWallet
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");
        require(permitOwners.length == payments.length, "Length mismatch: owners");
        require(permitSingles.length == payments.length, "Length mismatch: singles");
        require(permitSignatures.length == payments.length, "Length mismatch: signatures");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePermitAndPay(
                permitOwners[i],
                permitSingles[i],
                permitSignatures[i],
                payments[i],
                feeWallet
            ) {
                successCount++;
            } catch Error(string memory reason) {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, reason);
            } catch {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, "Unknown error");
            }
            unchecked { ++i; }
        }

        emit BatchCompleted(payments.length, successCount);
    }

    /**
     * @notice Multi-user batch payment (Permit2 AllowanceTransfer, for repeat payments)
     * @param payments Array of payments
     * @param feeWallet Address to receive fees
     */
    function batchPayFromMultiUser(
        Payment[] calldata payments,
        address feeWallet
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePaymentPermit2(payments[i], feeWallet) {
                successCount++;
            } catch Error(string memory reason) {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, reason);
            } catch {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, "Unknown error");
            }
            unchecked { ++i; }
        }

        emit BatchCompleted(payments.length, successCount);
    }

    /**
     * @notice Execute individual permit + pay (Permit2) - external for try-catch
     */
    function _executePermitAndPay(
        address permitOwner,
        IPermit2.PermitSingle calldata permitSingle,
        bytes calldata permitSignature,
        Payment calldata payment,
        address feeWallet
    ) external {
        require(msg.sender == address(this), "Internal only");

        if (permitSignature.length > 0) {
            permit2.permit(permitOwner, permitSingle, permitSignature);
        }

        _executePaymentPermit2Internal(payment, feeWallet);
    }

    /**
     * @notice Execute individual payment (Permit2) - external for try-catch
     */
    function _executePaymentPermit2(
        Payment calldata p,
        address feeWallet
    ) external {
        require(msg.sender == address(this), "Internal only");
        _executePaymentPermit2Internal(p, feeWallet);
    }

    /**
     * @notice Execute individual payment (Permit2) - internal implementation
     */
    function _executePaymentPermit2Internal(
        Payment calldata p,
        address feeWallet
    ) internal {
        _verifyServerSignature(p);
        require(block.timestamp <= p.deadline, "Payment expired");

        permit2.transferFrom(p.user, p.pool, uint160(p.amount), p.token);

        if (p.fee > 0 && feeWallet != address(0)) {
            permit2.transferFrom(p.user, feeWallet, uint160(p.fee), p.token);
        }

        emit PaymentExecuted(
            p.paymentId,
            p.user,
            p.to,
            p.pool,
            p.amount,
            p.fee
        );
    }

    // ============================================
    // External Functions - EIP-2612 Permit
    // ============================================

    /**
     * @notice Batch payment with EIP-2612 Permit (for USDC)
     * @param permitSignatures Array of EIP-2612 permit signatures
     * @param payments Array of payment info
     * @param feeWallet Address to receive fees
     */
    function batchPermitERC20AndPay(
        ERC20PermitSignature[] calldata permitSignatures,
        Payment[] calldata payments,
        address feeWallet
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");
        require(permitSignatures.length == payments.length, "Length mismatch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePermitERC20AndPay(
                permitSignatures[i],
                payments[i],
                feeWallet
            ) {
                successCount++;
            } catch Error(string memory reason) {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, reason);
            } catch {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, "Unknown error");
            }
            unchecked { ++i; }
        }

        emit BatchCompleted(payments.length, successCount);
    }

    /**
     * @notice Batch payment using existing ERC20 allowance (no permit needed)
     * @param payments Array of payment info
     * @param feeWallet Address to receive fees
     */
    function batchPayERC20(
        Payment[] calldata payments,
        address feeWallet
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePaymentERC20(payments[i], feeWallet) {
                successCount++;
            } catch Error(string memory reason) {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, reason);
            } catch {
                emit PaymentFailed(payments[i].paymentId, payments[i].user, payments[i].amount, "Unknown error");
            }
            unchecked { ++i; }
        }

        emit BatchCompleted(payments.length, successCount);
    }

    /**
     * @notice Execute individual EIP-2612 permit + pay - external for try-catch
     */
    function _executePermitERC20AndPay(
        ERC20PermitSignature calldata permitSig,
        Payment calldata payment,
        address feeWallet
    ) external {
        require(msg.sender == address(this), "Internal only");

        IERC20Permit(payment.token).permit(
            payment.user,
            address(this),
            permitSig.value,
            permitSig.deadline,
            permitSig.v,
            permitSig.r,
            permitSig.s
        );

        _executePaymentERC20Internal(payment, feeWallet);
    }

    /**
     * @notice Execute individual payment (ERC20) - external for try-catch
     */
    function _executePaymentERC20(
        Payment calldata p,
        address feeWallet
    ) external {
        require(msg.sender == address(this), "Internal only");
        _executePaymentERC20Internal(p, feeWallet);
    }

    /**
     * @notice Execute individual payment (ERC20) - internal implementation
     */
    function _executePaymentERC20Internal(
        Payment calldata p,
        address feeWallet
    ) internal {
        _verifyServerSignature(p);
        require(block.timestamp <= p.deadline, "Payment expired");

        IERC20(p.token).safeTransferFrom(p.user, p.pool, p.amount);

        if (p.fee > 0 && feeWallet != address(0)) {
            IERC20(p.token).safeTransferFrom(p.user, feeWallet, p.fee);
        }

        emit PaymentExecuted(
            p.paymentId,
            p.user,
            p.to,
            p.pool,
            p.amount,
            p.fee
        );
    }

    // ============================================
    // Internal Functions
    // ============================================

    function _verifyServerSignature(Payment calldata p) internal view {
        bytes32 structHash = keccak256(abi.encode(
            PAYMENT_TYPEHASH,
            p.paymentId,
            p.user,
            p.pool,
            p.to,
            p.token,
            p.amount,
            p.fee,
            p.deadline
        ));

        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = digest.recover(p.serverSignature);

        require(serverSigners[recovered], "Invalid server signature");
    }

    // ============================================
    // Admin Functions - Owner
    // ============================================

    function addServerSigner(address _serverSigner) external onlyOwner {
        require(_serverSigner != address(0), "Invalid serverSigner");
        require(!serverSigners[_serverSigner], "Already serverSigner");
        serverSigners[_serverSigner] = true;
        _serverSignerList.push(_serverSigner);
        emit ServerSignerAdded(_serverSigner);
    }

    function removeServerSigner(address _serverSigner) external onlyOwner {
        require(serverSigners[_serverSigner], "Not serverSigner");
        serverSigners[_serverSigner] = false;
        _removeFromArray(_serverSignerList, _serverSigner);
        emit ServerSignerRemoved(_serverSigner);
    }

    function addRelayer(address _relayer) external onlyOwner {
        require(_relayer != address(0), "Invalid relayer");
        require(!relayers[_relayer], "Already relayer");
        relayers[_relayer] = true;
        _relayerList.push(_relayer);
        emit RelayerAdded(_relayer);
    }

    function removeRelayer(address _relayer) external onlyOwner {
        require(relayers[_relayer], "Not relayer");
        relayers[_relayer] = false;
        _removeFromArray(_relayerList, _relayer);
        emit RelayerRemoved(_relayer);
    }

    function setEmergencyAdmin(address _emergencyAdmin) external onlyOwner {
        require(_emergencyAdmin != address(0), "Invalid emergencyAdmin");
        require(_emergencyAdmin != address(this), "EmergencyAdmin cannot be this contract");
        address oldAdmin = emergencyAdmin;
        emergencyAdmin = _emergencyAdmin;
        emit EmergencyAdminChanged(oldAdmin, _emergencyAdmin);
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid owner");
        require(_newOwner != address(this), "Owner cannot be this contract");
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerChanged(oldOwner, _newOwner);
    }

    // ============================================
    // Emergency Functions - EmergencyAdmin
    // ============================================

    function pause() external onlyEmergencyAdmin {
        require(!paused, "Already paused");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyEmergencyAdmin {
        require(paused, "Not paused");
        paused = false;
        emit Unpaused(msg.sender);
    }

    function emergencyAddServerSigner(address _serverSigner) external onlyEmergencyAdmin {
        require(_serverSigner != address(0), "Invalid serverSigner");
        if (!serverSigners[_serverSigner]) {
            serverSigners[_serverSigner] = true;
            _serverSignerList.push(_serverSigner);
        }
        emit ServerSignerAdded(_serverSigner);
    }

    function emergencyRemoveServerSigner(address _serverSigner) external onlyEmergencyAdmin {
        if (serverSigners[_serverSigner]) {
            serverSigners[_serverSigner] = false;
            _removeFromArray(_serverSignerList, _serverSigner);
        }
        emit ServerSignerRemoved(_serverSigner);
    }

    function emergencyAddRelayer(address _relayer) external onlyEmergencyAdmin {
        require(_relayer != address(0), "Invalid relayer");
        if (!relayers[_relayer]) {
            relayers[_relayer] = true;
            _relayerList.push(_relayer);
        }
        emit RelayerAdded(_relayer);
    }

    function emergencyRemoveRelayer(address _relayer) external onlyEmergencyAdmin {
        if (relayers[_relayer]) {
            relayers[_relayer] = false;
            _removeFromArray(_relayerList, _relayer);
        }
        emit RelayerRemoved(_relayer);
    }

    // ============================================
    // Internal Helper Functions
    // ============================================

    function _removeFromArray(address[] storage arr, address addr) internal {
        uint256 len = arr.length;
        for (uint256 i = 0; i < len; ) {
            if (arr[i] == addr) {
                arr[i] = arr[len - 1];
                arr.pop();
                return;
            }
            unchecked { ++i; }
        }
    }

    // ============================================
    // View Functions
    // ============================================

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function isServerSigner(address _addr) external view returns (bool) {
        return serverSigners[_addr];
    }

    function isRelayer(address _addr) external view returns (bool) {
        return relayers[_addr];
    }

    function getRelayers() external view returns (address[] memory) {
        return _relayerList;
    }

    function getServerSigners() external view returns (address[] memory) {
        return _serverSignerList;
    }

    function getRelayerCount() external view returns (uint256) {
        return _relayerList.length;
    }

    function getServerSignerCount() external view returns (uint256) {
        return _serverSignerList.length;
    }
}
