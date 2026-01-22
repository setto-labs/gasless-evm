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
 * @title SettoPaymentV4
 * @notice Gas-sponsored payment contract (Permit2 + EIP-2612 Permit)
 * @dev V4 Changes:
 *      - Added EIP-2612 Permit support for USDC (no initial approve TX needed)
 *      - Permit2 still supported for USDT and other tokens
 *      - Inherits all V3 features (multi-signer, no relayer check)
 */
contract SettoPaymentV4 is Initializable, EIP712Upgradeable, ReentrancyGuardUpgradeable, MulticallUpgradeable, UUPSUpgradeable {
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
    address public owner;              // Gnosis Safe 2/3
    address public emergencyAdmin;     // Individual wallet for emergency response
    mapping(address => bool) public relayers;        // V4: multi-relayer support (replay protection via off-chain DB)
    mapping(address => bool) public serverSigners;   // V3+: multi-signer support
    address public feeWallet;
    bool public paused;                // Emergency pause state

    // V4: 목록 조회용 배열 (mapping과 동기화)
    address[] private _relayerList;
    address[] private _serverSignerList;

    // ============================================
    // Structs
    // ============================================

    struct Payment {
        bytes32 paymentId;
        address user;
        address pool;      // Address to receive tokens (Pool)
        address token;
        uint256 amount;
        uint256 fee;
        uint256 deadline;
        address to;        // Settlement target address (for event logging)
        bytes serverSignature;
    }

    /// @notice EIP-2612 Permit signature data
    struct ERC20PermitSignature {
        uint256 value;      // Allowance amount
        uint256 deadline;   // Permit deadline
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
    event FeeWalletChanged(address indexed oldWallet, address indexed newWallet);
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
        address _serverSigner,
        address _relayer,
        address _feeWallet
    ) public initializer {
        require(_owner != address(0), "Invalid owner");
        require(_emergencyAdmin != address(0), "Invalid emergencyAdmin");
        require(_serverSigner != address(0), "Invalid serverSigner");
        require(_relayer != address(0), "Invalid relayer");
        require(_feeWallet != address(0), "Invalid feeWallet");

        __EIP712_init("SettoPayment", "1");
        __ReentrancyGuard_init();
        __Multicall_init();
        __UUPSUpgradeable_init();

        owner = _owner;
        emergencyAdmin = _emergencyAdmin;
        serverSigners[_serverSigner] = true;
        _serverSignerList.push(_serverSigner);
        relayers[_relayer] = true;
        _relayerList.push(_relayer);
        feeWallet = _feeWallet;

        emit ServerSignerAdded(_serverSigner);
        emit RelayerAdded(_relayer);
    }

    /**
     * @notice Reinitialize for V4 upgrade - reset all settings
     * @dev Overwrites all role settings (one-time only via reinitializer)
     */
    function initializeV4(
        address _owner,
        address _emergencyAdmin,
        address _serverSigner,
        address _relayer,
        address _feeWallet
    ) public reinitializer(4) {
        require(_owner != address(0), "Invalid owner");
        require(_emergencyAdmin != address(0), "Invalid emergencyAdmin");
        require(_serverSigner != address(0), "Invalid serverSigner");
        require(_relayer != address(0), "Invalid relayer");
        require(_feeWallet != address(0), "Invalid feeWallet");

        owner = _owner;
        emergencyAdmin = _emergencyAdmin;
        serverSigners[_serverSigner] = true;
        _serverSignerList.push(_serverSigner);
        relayers[_relayer] = true;
        _relayerList.push(_relayer);
        feeWallet = _feeWallet;

        emit OwnerChanged(address(0), _owner);
        emit EmergencyAdminChanged(address(0), _emergencyAdmin);
        emit ServerSignerAdded(_serverSigner);
        emit RelayerAdded(_relayer);
        emit FeeWalletChanged(address(0), _feeWallet);
    }

    // ============================================
    // UUPS Upgrade Authorization
    // ============================================

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ============================================
    // External Functions - Permit2 (from V3)
    // ============================================

    /**
     * @notice Set Permit2 allowance + batch payment processing (for first-time payments)
     * @dev Anyone can call this - serverSignature is the only authorization
     * @param permitOwners Array of Permit2 signers (token owners)
     * @param permitSingles Array of Permit2 PermitSingle structs
     * @param permitSignatures Array of Permit2 signatures (empty bytes skips permit)
     * @param payments Array of payment info
     */
    function batchPermitAndPay(
        address[] calldata permitOwners,
        IPermit2.PermitSingle[] calldata permitSingles,
        bytes[] calldata permitSignatures,
        Payment[] calldata payments
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
                payments[i]
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
     * @dev Anyone can call this - serverSignature is the only authorization
     * @param payments Array of payments
     */
    function batchPayFromMultiUser(
        Payment[] calldata payments
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePaymentPermit2(payments[i]) {
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
        Payment calldata payment
    ) external {
        require(msg.sender == address(this), "Internal only");

        if (permitSignature.length > 0) {
            permit2.permit(permitOwner, permitSingle, permitSignature);
        }

        _executePaymentPermit2Internal(payment);
    }

    /**
     * @notice Execute individual payment (Permit2) - external for try-catch
     */
    function _executePaymentPermit2(
        Payment calldata p
    ) external {
        require(msg.sender == address(this), "Internal only");
        _executePaymentPermit2Internal(p);
    }

    /**
     * @notice Execute individual payment (Permit2) - internal implementation
     */
    function _executePaymentPermit2Internal(
        Payment calldata p
    ) internal {
        _verifyServerSignature(p);
        require(block.timestamp <= p.deadline, "Payment expired");

        permit2.transferFrom(p.user, p.pool, uint160(p.amount), p.token);

        if (p.fee > 0) {
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
    // External Functions - EIP-2612 Permit (V4 NEW)
    // ============================================

    /**
     * @notice Batch payment with EIP-2612 Permit (for USDC)
     * @dev No initial approve TX needed - permit signature sets allowance directly
     *      Use this for USDC. For USDT, use Permit2 functions.
     * @param permitSignatures Array of EIP-2612 permit signatures
     * @param payments Array of payment info
     */
    function batchPermitERC20AndPay(
        ERC20PermitSignature[] calldata permitSignatures,
        Payment[] calldata payments
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");
        require(permitSignatures.length == payments.length, "Length mismatch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePermitERC20AndPay(
                permitSignatures[i],
                payments[i]
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
     * @dev Use this when user has already approved this contract via ERC20.approve()
     * @param payments Array of payment info
     */
    function batchPayERC20(
        Payment[] calldata payments
    ) external onlyRelayer whenNotPaused {
        require(payments.length > 0, "Empty batch");

        uint256 successCount = 0;

        for (uint256 i = 0; i < payments.length; ) {
            try this._executePaymentERC20(payments[i]) {
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
        Payment calldata payment
    ) external {
        require(msg.sender == address(this), "Internal only");

        // Execute EIP-2612 permit (sets allowance)
        IERC20Permit(payment.token).permit(
            payment.user,
            address(this),
            permitSig.value,
            permitSig.deadline,
            permitSig.v,
            permitSig.r,
            permitSig.s
        );

        _executePaymentERC20Internal(payment);
    }

    /**
     * @notice Execute individual payment (ERC20) - external for try-catch
     */
    function _executePaymentERC20(
        Payment calldata p
    ) external {
        require(msg.sender == address(this), "Internal only");
        _executePaymentERC20Internal(p);
    }

    /**
     * @notice Execute individual payment (ERC20) - internal implementation
     * @dev Uses safeTransferFrom instead of Permit2
     */
    function _executePaymentERC20Internal(
        Payment calldata p
    ) internal {
        _verifyServerSignature(p);
        require(block.timestamp <= p.deadline, "Payment expired");

        // Direct ERC20 transfer (to pool)
        IERC20(p.token).safeTransferFrom(p.user, p.pool, p.amount);

        // Direct ERC20 transfer (to feeWallet, if fee exists)
        if (p.fee > 0) {
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

    /**
     * @notice Verify server signature
     * @param p Payment struct
     */
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
    // Admin Functions - Owner (Gnosis Safe 2/3)
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

    function setFeeWallet(address _feeWallet) external onlyOwner {
        require(_feeWallet != address(0), "Invalid feeWallet");
        address oldWallet = feeWallet;
        feeWallet = _feeWallet;
        emit FeeWalletChanged(oldWallet, _feeWallet);
    }

    function setEmergencyAdmin(address _emergencyAdmin) external onlyOwner {
        require(_emergencyAdmin != address(0), "Invalid emergencyAdmin");
        address oldAdmin = emergencyAdmin;
        emergencyAdmin = _emergencyAdmin;
        emit EmergencyAdminChanged(oldAdmin, _emergencyAdmin);
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid owner");
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

    function emergencySetFeeWallet(address _feeWallet) external onlyEmergencyAdmin {
        require(_feeWallet != address(0), "Invalid feeWallet");
        address oldWallet = feeWallet;
        feeWallet = _feeWallet;
        emit FeeWalletChanged(oldWallet, _feeWallet);
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
