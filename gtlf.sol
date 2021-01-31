// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

/**
 * @title Proxy
 * @dev Implements delegation of calls to other contracts, with proper
 * forwarding of return values and bubbling of failures.
 * It defines a fallback function that delegates all calls to the address
 * returned by the abstract _implementation() internal function.
 */
abstract contract Proxy {
  /**
   * @dev Fallback function.
   * Implemented entirely in `_fallback`.
   */
  fallback () payable external {
    _fallback();
  }
  
  receive () payable external {
    _fallback();
  }

  /**
   * @return The Address of the implementation.
   */
  function _implementation() virtual internal view returns (address);

  /**
   * @dev Delegates execution to an implementation contract.
   * This is a low level function that doesn't return to its internal call site.
   * It will return to the external caller whatever the implementation returns.
   * @param implementation Address to delegate.
   */
  function _delegate(address implementation) internal {
    assembly {
      // Copy msg.data. We take full control of memory in this inline assembly
      // block because it will not return to Solidity code. We overwrite the
      // Solidity scratch pad at memory position 0.
      calldatacopy(0, 0, calldatasize())

      // Call the implementation.
      // out and outsize are 0 because we don't know the size yet.
      let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

      // Copy the returned data.
      returndatacopy(0, 0, returndatasize())

      switch result
      // delegatecall returns 0 on error.
      case 0 { revert(0, returndatasize()) }
      default { return(0, returndatasize()) }
    }
  }

  /**
   * @dev Function that is run as the first thing in the fallback function.
   * Can be redefined in derived contracts to add functionality.
   * Redefinitions must call super._willFallback().
   */
  function _willFallback() virtual internal {
      
  }

  /**
   * @dev fallback implementation.
   * Extracted to enable manual triggering.
   */
  function _fallback() internal {
    if(OpenZeppelinUpgradesAddress.isContract(msg.sender) && msg.data.length == 0 && gasleft() <= 2300)         // for receive ETH only from other contract
        return;
    _willFallback();
    _delegate(_implementation());
  }
}


/**
 * @title BaseUpgradeabilityProxy
 * @dev This contract implements a proxy that allows to change the
 * implementation address to which it will delegate.
 * Such a change is called an implementation upgrade.
 */
abstract contract BaseUpgradeabilityProxy is Proxy {
  /**
   * @dev Emitted when the implementation is upgraded.
   * @param implementation Address of the new implementation.
   */
  event Upgraded(address indexed implementation);

  /**
   * @dev Storage slot with the address of the current implementation.
   * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
   * validated in the constructor.
   */
  bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

  /**
   * @dev Returns the current implementation.
   * @return impl Address of the current implementation
   */
  function _implementation() override internal view returns (address impl) {
    bytes32 slot = IMPLEMENTATION_SLOT;
    assembly {
      impl := sload(slot)
    }
  }

  /**
   * @dev Upgrades the proxy to a new implementation.
   * @param newImplementation Address of the new implementation.
   */
  function _upgradeTo(address newImplementation) internal {
    _setImplementation(newImplementation);
    emit Upgraded(newImplementation);
  }

  /**
   * @dev Sets the implementation address of the proxy.
   * @param newImplementation Address of the new implementation.
   */
  function _setImplementation(address newImplementation) internal {
    require(OpenZeppelinUpgradesAddress.isContract(newImplementation), "Cannot set a proxy implementation to a non-contract address");

    bytes32 slot = IMPLEMENTATION_SLOT;

    assembly {
      sstore(slot, newImplementation)
    }
  }
}


/**
 * @title BaseAdminUpgradeabilityProxy
 * @dev This contract combines an upgradeability proxy with an authorization
 * mechanism for administrative tasks.
 * All external functions in this contract must be guarded by the
 * `ifAdmin` modifier. See ethereum/solidity#3864 for a Solidity
 * feature proposal that would enable this to be done automatically.
 */
contract BaseAdminUpgradeabilityProxy is BaseUpgradeabilityProxy {
  /**
   * @dev Emitted when the administration has been transferred.
   * @param previousAdmin Address of the previous admin.
   * @param newAdmin Address of the new admin.
   */
  event AdminChanged(address previousAdmin, address newAdmin);

  /**
   * @dev Storage slot with the admin of the contract.
   * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
   * validated in the constructor.
   */

  bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

  /**
   * @dev Modifier to check whether the `msg.sender` is the admin.
   * If it is, it will run the function. Otherwise, it will delegate the call
   * to the implementation.
   */
  modifier ifAdmin() {
    if (msg.sender == _admin()) {
      _;
    } else {
      _fallback();
    }
  }

  /**
   * @return The address of the proxy admin.
   */
  function admin() external ifAdmin returns (address) {
    return _admin();
  }

  /**
   * @return The address of the implementation.
   */
  function implementation() external ifAdmin returns (address) {
    return _implementation();
  }

  /**
   * @dev Changes the admin of the proxy.
   * Only the current admin can call this function.
   * @param newAdmin Address to transfer proxy administration to.
   */
  function changeAdmin(address newAdmin) external ifAdmin {
    require(newAdmin != address(0), "Cannot change the admin of a proxy to the zero address");
    emit AdminChanged(_admin(), newAdmin);
    _setAdmin(newAdmin);
  }

  /**
   * @dev Upgrade the backing implementation of the proxy.
   * Only the admin can call this function.
   * @param newImplementation Address of the new implementation.
   */
  function upgradeTo(address newImplementation) external ifAdmin {
    _upgradeTo(newImplementation);
  }

  /**
   * @dev Upgrade the backing implementation of the proxy and call a function
   * on the new implementation.
   * This is useful to initialize the proxied contract.
   * @param newImplementation Address of the new implementation.
   * @param data Data to send as msg.data in the low level call.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   */
  function upgradeToAndCall(address newImplementation, bytes calldata data) payable external ifAdmin {
    _upgradeTo(newImplementation);
    (bool success,) = newImplementation.delegatecall(data);
    require(success);
  }

  /**
   * @return adm The admin slot.
   */
  function _admin() internal view returns (address adm) {
    bytes32 slot = ADMIN_SLOT;
    assembly {
      adm := sload(slot)
    }
  }

  /**
   * @dev Sets the address of the proxy admin.
   * @param newAdmin Address of the new proxy admin.
   */
  function _setAdmin(address newAdmin) internal {
    bytes32 slot = ADMIN_SLOT;

    assembly {
      sstore(slot, newAdmin)
    }
  }

  /**
   * @dev Only fall back when the sender is not the admin.
   */
  function _willFallback() virtual override internal {
    require(msg.sender != _admin(), "Cannot call fallback function from the proxy admin");
    //super._willFallback();
  }
}

interface IAdminUpgradeabilityProxyView {
  function admin() external view returns (address);
  function implementation() external view returns (address);
}


/**
 * @title UpgradeabilityProxy
 * @dev Extends BaseUpgradeabilityProxy with a constructor for initializing
 * implementation and init data.
 */
abstract contract UpgradeabilityProxy is BaseUpgradeabilityProxy {
  /**
   * @dev Contract constructor.
   * @param _logic Address of the initial implementation.
   * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
   */
  constructor(address _logic, bytes memory _data) public payable {
    assert(IMPLEMENTATION_SLOT == bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1));
    _setImplementation(_logic);
    if(_data.length > 0) {
      (bool success,) = _logic.delegatecall(_data);
      require(success);
    }
  }  
  
  //function _willFallback() virtual override internal {
    //super._willFallback();
  //}
}


/**
 * @title AdminUpgradeabilityProxy
 * @dev Extends from BaseAdminUpgradeabilityProxy with a constructor for 
 * initializing the implementation, admin, and init data.
 */
contract AdminUpgradeabilityProxy is BaseAdminUpgradeabilityProxy, UpgradeabilityProxy {
  /**
   * Contract constructor.
   * @param _logic address of the initial implementation.
   * @param _admin Address of the proxy administrator.
   * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
   */
  constructor(address _admin, address _logic, bytes memory _data) UpgradeabilityProxy(_logic, _data) public payable {
    assert(ADMIN_SLOT == bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1));
    _setAdmin(_admin);
  }
  
  function _willFallback() override(Proxy, BaseAdminUpgradeabilityProxy) internal {
    super._willFallback();
  }
}


/**
 * @title InitializableUpgradeabilityProxy
 * @dev Extends BaseUpgradeabilityProxy with an initializer for initializing
 * implementation and init data.
 */
abstract contract InitializableUpgradeabilityProxy is BaseUpgradeabilityProxy {
  /**
   * @dev Contract initializer.
   * @param _logic Address of the initial implementation.
   * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
   */
  function initialize(address _logic, bytes memory _data) public payable {
    require(_implementation() == address(0));
    assert(IMPLEMENTATION_SLOT == bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1));
    _setImplementation(_logic);
    if(_data.length > 0) {
      (bool success,) = _logic.delegatecall(_data);
      require(success);
    }
  }  
}


/**
 * @title InitializableAdminUpgradeabilityProxy
 * @dev Extends from BaseAdminUpgradeabilityProxy with an initializer for 
 * initializing the implementation, admin, and init data.
 */
contract InitializableAdminUpgradeabilityProxy is BaseAdminUpgradeabilityProxy, InitializableUpgradeabilityProxy {
  /**
   * Contract initializer.
   * @param _logic address of the initial implementation.
   * @param _admin Address of the proxy administrator.
   * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
   */
  function initialize(address _admin, address _logic, bytes memory _data) public payable {
    require(_implementation() == address(0));
    InitializableUpgradeabilityProxy.initialize(_logic, _data);
    assert(ADMIN_SLOT == bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1));
    _setAdmin(_admin);
  }
  
  function _willFallback() override(Proxy, BaseAdminUpgradeabilityProxy) internal {
    super._willFallback();
  }

}


interface IProxyFactory {
    function productImplementation() external view returns (address);
    function productImplementations(bytes32 name) external view returns (address);
}


/**
 * @title ProductProxy
 * @dev This contract implements a proxy that 
 * it is deploied by ProxyFactory, 
 * and it's implementation is stored in factory.
 */
contract ProductProxy is Proxy {
    
  /**
   * @dev Storage slot with the address of the ProxyFactory.
   * This is the keccak-256 hash of "eip1967.proxy.factory" subtracted by 1, and is
   * validated in the constructor.
   */
  bytes32 internal constant FACTORY_SLOT = 0x7a45a402e4cb6e08ebc196f20f66d5d30e67285a2a8aa80503fa409e727a4af1;

  function productName() virtual public pure returns (bytes32) {
    return 0x0;
  }

  /**
   * @dev Sets the factory address of the ProductProxy.
   * @param newFactory Address of the new factory.
   */
  function _setFactory(address newFactory) internal {
    require(OpenZeppelinUpgradesAddress.isContract(newFactory), "Cannot set a factory to a non-contract address");

    bytes32 slot = FACTORY_SLOT;

    assembly {
      sstore(slot, newFactory)
    }
  }

  /**
   * @dev Returns the factory.
   * @return factory Address of the factory.
   */
  function _factory() internal view returns (address factory) {
    bytes32 slot = FACTORY_SLOT;
    assembly {
      factory := sload(slot)
    }
  }
  
  /**
   * @dev Returns the current implementation.
   * @return Address of the current implementation
   */
  function _implementation() virtual override internal view returns (address) {
    address factory = _factory();
    if(OpenZeppelinUpgradesAddress.isContract(factory))
        return IProxyFactory(factory).productImplementations(productName());
    else
        return address(0);
  }

}


/**
 * @title InitializableProductProxy
 * @dev Extends ProductProxy with an initializer for initializing
 * factory and init data.
 */
contract InitializableProductProxy is ProductProxy {
  /**
   * @dev Contract initializer.
   * @param factory Address of the initial factory.
   * @param data Data to send as msg.data to the implementation to initialize the proxied contract.
   * It should include the signature and the parameters of the function to be called, as described in
   * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
   * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
   */
  function initialize(address factory, bytes memory data) public payable {
    require(_factory() == address(0));
    assert(FACTORY_SLOT == bytes32(uint256(keccak256('eip1967.proxy.factory')) - 1));
    _setFactory(factory);
    if(data.length > 0) {
      (bool success,) = _implementation().delegatecall(data);
      require(success);
    }
  }  
}


/**
 * Utility library of inline functions on addresses
 *
 * Source https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-solidity/v2.1.3/contracts/utils/Address.sol
 * This contract is copied here and renamed from the original to avoid clashes in the compiled artifacts
 * when the user imports a zos-lib contract (that transitively causes this contract to be compiled and added to the
 * build/artifacts folder) as well as the vanilla Address implementation from an openzeppelin version.
 */
library OpenZeppelinUpgradesAddress {
    /**
     * Returns whether the target address is a contract
     * @dev This function will return false if invoked during the constructor of a contract,
     * as the code is not actually created until after the constructor finishes.
     * @param account address of the account to check
     * @return whether the target address is a contract
     */
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        // XXX Currently there is no better way to check if there is a contract in an address
        // than to check the size of the code at that address.
        // See https://ethereum.stackexchange.com/a/14016/36603
        // for more details about how this works.
        // TODO Check this again before the Serenity release, because all addresses will be
        // contracts then.
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}


/**
 * @title Initializable
 *
 * @dev Helper contract to support initializer functions. To use it, replace
 * the constructor with a function that has the `initializer` modifier.
 * WARNING: Unlike constructors, initializer functions must be manually
 * invoked. This applies both to deploying an Initializable contract, as well
 * as extending an Initializable contract via inheritance.
 * WARNING: When used with inheritance, manual care must be taken to not invoke
 * a parent initializer twice, or ensure that all initializers are idempotent,
 * because this is not dealt with automatically as with constructors.
 */
contract Initializable {

  /**
   * @dev Indicates that the contract has been initialized.
   */
  bool private initialized;

  /**
   * @dev Indicates that the contract is in the process of being initialized.
   */
  bool private initializing;

  /**
   * @dev Modifier to use in the initializer function of a contract.
   */
  modifier initializer() {
    require(initializing || isConstructor() || !initialized, "Contract instance has already been initialized");

    bool isTopLevelCall = !initializing;
    if (isTopLevelCall) {
      initializing = true;
      initialized = true;
    }

    _;

    if (isTopLevelCall) {
      initializing = false;
    }
  }

  /// @dev Returns true if and only if the function is running in the constructor
  function isConstructor() private view returns (bool) {
    // extcodesize checks the size of the code stored in an address, and
    // address returns the current address. Since the code is still not
    // deployed when running a constructor, any checks on its code size will
    // yield zero, making it an effective way to detect if a contract is
    // under construction or not.
    address self = address(this);
    uint256 cs;
    assembly { cs := extcodesize(self) }
    return cs == 0;
  }

  // Reserved storage space to allow for layout changes in the future.
  uint256[50] private ______gap;
}


/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
contract ContextUpgradeSafe is Initializable {
    // Empty internal constructor, to prevent people from mistakenly deploying
    // an instance of this contract, which should be used via inheritance.

    function __Context_init() internal initializer {
        __Context_init_unchained();
    }

    function __Context_init_unchained() internal initializer {


    }


    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }

    uint256[50] private __gap;
}

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow, so we distribute
        return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);
    }
}

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function sub0(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != accountHash && codehash != 0x0);
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 * For a generic mechanism see {ERC20MinterPauser}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * We have followed general OpenZeppelin guidelines: functions revert instead
 * of returning `false` on failure. This behavior is nonetheless conventional
 * and does not conflict with the expectations of ERC20 applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the EIP may not emit
 * these events, as it isn't required by the specification.
 *
 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}
 * functions have been added to mitigate the well-known issues around setting
 * allowances. See {IERC20-approve}.
 */
contract ERC20UpgradeSafe is Initializable, ContextUpgradeSafe, IERC20 {
    using SafeMath for uint256;
    using Address for address;

    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    /**
     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with
     * a default value of 18.
     *
     * To select a different value for {decimals}, use {_setupDecimals}.
     *
     * All three of these values are immutable: they can only be set once during
     * construction.
     */

    function __ERC20_init(string memory name, string memory symbol) internal initializer {
        __Context_init_unchained();
        __ERC20_init_unchained(name, symbol);
    }

    function __ERC20_init_unchained(string memory name, string memory symbol) internal initializer {


        _name = name;
        _symbol = symbol;
        _decimals = 18;

    }


    /**
     * @dev Returns the name of the token.
     */
    function name() public view returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is
     * called.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view returns (uint8) {
        return _decimals;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20};
     *
     * Requirements:
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for ``sender``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner`s tokens.
     *
     * This is internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Sets {decimals} to a value other than the default one of 18.
     *
     * WARNING: This function should only be called from the constructor. Most
     * applications that interact with token contracts will not expect
     * {decimals} to ever change, and may work incorrectly if it does.
     */
    function _setupDecimals(uint8 decimals_) internal {
        _decimals = decimals_;
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }

    uint256[44] private __gap;
}


/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for ERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}


contract Governable is Initializable {
    address public governor;

    event GovernorshipTransferred(address indexed previousGovernor, address indexed newGovernor);

    /**
     * @dev Contract initializer.
     * called once by the factory at time of deployment
     */
    function __Governable_init(address governor_) virtual public initializer {
        governor = governor_;
        emit GovernorshipTransferred(address(0), governor);
    }

    modifier governance() {
        require(msg.sender == governor);
        _;
    }

    /**
     * @dev Allows the current governor to relinquish control of the contract.
     * @notice Renouncing to governorship will leave the contract without an governor.
     * It will not be possible to call the functions with the `governance`
     * modifier anymore.
     */
    function renounceGovernorship() public governance {
        emit GovernorshipTransferred(governor, address(0));
        governor = address(0);
    }

    /**
     * @dev Allows the current governor to transfer control of the contract to a newGovernor.
     * @param newGovernor The address to transfer governorship to.
     */
    function transferGovernorship(address newGovernor) public governance {
        _transferGovernorship(newGovernor);
    }

    /**
     * @dev Transfers control of the contract to a newGovernor.
     * @param newGovernor The address to transfer governorship to.
     */
    function _transferGovernorship(address newGovernor) internal {
        require(newGovernor != address(0));
        emit GovernorshipTransferred(governor, newGovernor);
        governor = newGovernor;
    }
}


contract Configurable is Governable {

    mapping (bytes32 => uint) internal config;
    
    function getConfig(bytes32 key) public view returns (uint) {
        return config[key];
    }
    function getConfig(bytes32 key, uint index) public view returns (uint) {
        return config[bytes32(uint(key) ^ index)];
    }
    function getConfig(bytes32 key, address addr) public view returns (uint) {
        return config[bytes32(uint(key) ^ uint(addr))];
    }

    function _setConfig(bytes32 key, uint value) internal {
        if(config[key] != value)
            config[key] = value;
    }
    function _setConfig(bytes32 key, uint index, uint value) internal {
        _setConfig(bytes32(uint(key) ^ index), value);
    }
    function _setConfig(bytes32 key, address addr, uint value) internal {
        _setConfig(bytes32(uint(key) ^ uint(addr)), value);
    }
    
    function setConfig(bytes32 key, uint value) external governance {
        _setConfig(key, value);
    }
    function setConfig(bytes32 key, uint index, uint value) external governance {
        _setConfig(bytes32(uint(key) ^ index), value);
    }
    function setConfig(bytes32 key, address addr, uint value) public governance {
        _setConfig(bytes32(uint(key) ^ uint(addr)), value);
    }
}


//import '@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol';
interface IUniswapV2Factory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function allPairsLength() external view returns (uint);

    function createPair(address tokenA, address tokenB) external returns (address pair);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
}

//import '@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol';
interface IUniswapV2Pair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;
}

//import '../libraries/UniswapV2Library.sol';
library UniswapV2Library {
    using SafeMath for uint;

    // returns sorted token addresses, used to handle return values from pairs sorted in this order
    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {
        require(tokenA != tokenB, 'UniswapV2Library: IDENTICAL_ADDRESSES');
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), 'UniswapV2Library: ZERO_ADDRESS');
    }

    // calculates the CREATE2 address for a pair without making any external calls
    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {
        bytes32 initCodeHash;
        assembly {
            switch chainid() 
                case 128 { initCodeHash := 0x2ad889f82040abccb2649ea6a874796c1601fb67f91a747a80e08860c73ddf24 }     // HECO Mainnet MDEX
                default  { initCodeHash := 0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f }     // Ethereum
        }
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(uint(keccak256(abi.encodePacked(
                hex'ff',
                factory,
                keccak256(abi.encodePacked(token0, token1)),
                initCodeHash
                //hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f' // init code hash
                //bytes32(0x2ad889f82040abccb2649ea6a874796c1601fb67f91a747a80e08860c73ddf24)      // MDEX
            ))));
    }

    // fetches and sorts the reserves for a pair
    function getReserves(address factory, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {
        (address token0,) = sortTokens(tokenA, tokenB);
        (uint reserve0, uint reserve1,) = IUniswapV2Pair(pairFor(factory, tokenA, tokenB)).getReserves();
        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
    }

    // given some amount of an asset and pair reserves, returns an equivalent amount of the other asset
    function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {
        require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');
        require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        amountB = amountA.mul(reserveB) / reserveA;
    }

    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {
        require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint amountInWithFee = amountIn.mul(997);
        uint numerator = amountInWithFee.mul(reserveOut);
        uint denominator = reserveIn.mul(1000).add(amountInWithFee);
        amountOut = numerator / denominator;
    }

    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {
        require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint numerator = reserveIn.mul(amountOut).mul(1000);
        uint denominator = reserveOut.sub(amountOut).mul(997);
        amountIn = (numerator / denominator).add(1);
    }

    // performs chained getAmountOut calculations on any number of pairs
    function getAmountsOut(address factory, uint amountIn, address[] memory path) internal view returns (uint[] memory amounts) {
        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[0] = amountIn;
        for (uint i; i < path.length - 1; i++) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i], path[i + 1]);
            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);
        }
    }

    // performs chained getAmountIn calculations on any number of pairs
    function getAmountsIn(address factory, uint amountOut, address[] memory path) internal view returns (uint[] memory amounts) {
        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[amounts.length - 1] = amountOut;
        for (uint i = path.length - 1; i > 0; i--) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i - 1], path[i]);
            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);
        }
    }
}

interface IUniswapV2Router01 {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);
    function WHT() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

interface IUniswapV2Router02 is IUniswapV2Router01 {
    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountETH);
    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountETH);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}


/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
contract ReentrancyGuardUpgradeSafe is Initializable {
    bool private _notEntered;


    function __ReentrancyGuard_init() internal initializer {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal initializer {


        // Storing an initial non-zero value makes deployment a bit more
        // expensive, but in exchange the refund on every call to nonReentrant
        // will be lower in amount. Since refunds are capped to a percetange of
        // the total transaction's gas, it is best to keep them low in cases
        // like this one, to increase the likelihood of the full refund coming
        // into effect.
        _notEntered = true;

    }


    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_notEntered, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _notEntered = false;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _notEntered = true;
    }

    uint256[49] private __gap;
}


// Inheritancea
interface IStakingRewards {
    // Views
    function lastTimeRewardApplicable() external view returns (uint256);

    function rewardPerToken() external view returns (uint256);

    function rewards(address account) external view returns (uint256);

    function earned(address account) external view returns (uint256);

    function getRewardForDuration() external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    // Mutative

    function stake(uint256 amount) external;

    function withdraw(uint256 amount) external;

    function getReward() external;

    function exit() external;
}

abstract contract RewardsDistributionRecipient {
    address public rewardsDistribution;

    // comment for reduce code size
    //function notifyRewardAmount(uint256 reward) virtual external;
    //
    //modifier onlyRewardsDistribution() {
    //    require(msg.sender == rewardsDistribution, "Caller is not RewardsDistribution contract");
    //    _;
    //}
}

contract StakingRewards is IStakingRewards, RewardsDistributionRecipient, ReentrancyGuardUpgradeSafe {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    /* ========== STATE VARIABLES ========== */

    IERC20 public rewardsToken;
    IERC20 public stakingToken;
    uint256 public periodFinish = 0;
    uint256 public rewardRate = 0;                  // obsoleted
    uint256 public rewardsDuration = 60 days;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) override public rewards;

    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balances;

    /* ========== CONSTRUCTOR ========== */

    //constructor(
    function __StakingRewards_init(
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken
    ) public virtual initializer {
        __ReentrancyGuard_init();
        rewardsToken = IERC20(_rewardsToken);
        stakingToken = IERC20(_stakingToken);
        rewardsDistribution = _rewardsDistribution;
    }

    /* ========== VIEWS ========== */

    function totalSupply() virtual override public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) virtual override public view returns (uint256) {
        return _balances[account];
    }

    function lastTimeRewardApplicable() override public view returns (uint256) {
        return Math.min(block.timestamp, periodFinish);
    }

    function rewardPerToken() virtual override public view returns (uint256) {
        if (_totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored.add(
                lastTimeRewardApplicable().sub(lastUpdateTime).mul(rewardRate).mul(1e18).div(_totalSupply)
            );
    }

    function earned(address account) virtual override public view returns (uint256) {
        return _balances[account].mul(rewardPerToken().sub(userRewardPerTokenPaid[account])).div(1e18).add(rewards[account]);
    }

    function getRewardForDuration() virtual override external view returns (uint256) {
        return rewardRate.mul(rewardsDuration);
    }

    /* ========== MUTATIVE FUNCTIONS ========== */
    // comment for reduce code size
    //function stakeWithPermit(uint256 amount, uint deadline, uint8 v, bytes32 r, bytes32 s) virtual public nonReentrant updateReward(msg.sender) {
    //    require(amount > 0, "Cannot stake 0");
    //    _totalSupply = _totalSupply.add(amount);
    //    _balances[msg.sender] = _balances[msg.sender].add(amount);
    //
    //    // permit
    //    IPermit(address(stakingToken)).permit(msg.sender, address(this), amount, deadline, v, r, s);
    //
    //    stakingToken.safeTransferFrom(msg.sender, address(this), amount);
    //    emit Staked(msg.sender, amount);
    //}

    function stake(uint256 amount) virtual override public {
        _stake(msg.sender, amount);
    }
    function _stake(address acct, uint256 amount) virtual internal nonReentrant updateReward(acct) {
        require(amount > 0, "Cannot stake 0");
        _totalSupply = _totalSupply.add(amount);
        _balances[acct] = _balances[acct].add(amount);
        stakingToken.safeTransferFrom(acct, address(this), amount);
        emit Staked(acct, amount);
    }

    function withdraw(uint256 amount) virtual override public {
        _withdraw(msg.sender, amount);
    }
    function _withdraw(address acct, uint256 amount) virtual internal nonReentrant updateReward(acct) {
        require(amount > 0, "Cannot withdraw 0");
        _totalSupply = _totalSupply.sub(amount);
        _balances[acct] = _balances[acct].sub(amount);
        stakingToken.safeTransfer(acct, amount);
        emit Withdrawn(acct, amount);
    }

    function getReward() virtual override public {
        _getReward(msg.sender);
    }
    function _getReward(address acct) virtual internal nonReentrant updateReward(acct) {
        uint256 reward = rewards[acct];
        if (reward > 0) {
            rewards[acct] = 0;
            rewardsToken.safeTransfer(acct, reward);
            emit RewardPaid(acct, reward);
        }
    }

    function exit() virtual override public {
        _exit(msg.sender);
    }
    function _exit(address acct) virtual internal {
        _getReward(acct);
        _withdraw(acct, _balances[acct]);
    }

    /* ========== RESTRICTED FUNCTIONS ========== */
    // comment for reduce code size
    //function notifyRewardAmount(uint256 reward) override external onlyRewardsDistribution updateReward(address(0)) {
    //    if (block.timestamp >= periodFinish) {
    //        rewardRate = reward.div(rewardsDuration);
    //    } else {
    //        uint256 remaining = periodFinish.sub(block.timestamp);
    //        uint256 leftover = remaining.mul(rewardRate);
    //        rewardRate = reward.add(leftover).div(rewardsDuration);
    //    }
    //
    //    // Ensure the provided reward amount is not more than the balance in the contract.
    //    // This keeps the reward rate in the right range, preventing overflows due to
    //    // very high values of rewardRate in the earned and rewardsPerToken functions;
    //    // Reward + leftover must be less than 2^256 / 10^18 to avoid overflow.
    //    uint balance = rewardsToken.balanceOf(address(this));
    //    require(rewardRate <= balance.div(rewardsDuration), "Provided reward too high");
    //
    //    lastUpdateTime = block.timestamp;
    //    periodFinish = block.timestamp.add(rewardsDuration);
    //    emit RewardAdded(reward);
    //}

    /* ========== MODIFIERS ========== */

    modifier updateReward(address account) virtual {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    /* ========== EVENTS ========== */

    event RewardAdded(uint256 reward);
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
}

interface IPermit {
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
}

contract StakingPool is Configurable, StakingRewards {
    using Address for address;
    
    bytes32 internal constant _ecoAddr_         = 'ecoAddr';
    bytes32 internal constant _ecoRatio_        = 'ecoRatio';
	bytes32 internal constant _allowContract_   = 'allowContract';
	bytes32 internal constant _allowlist_       = 'allowlist';
	bytes32 internal constant _blocklist_       = 'blocklist';
	
	bytes32 internal constant _rewards2Token_   = 'rewards2Token';
	bytes32 internal constant _rewards2Ratio_   = 'rewards2Ratio';
	//bytes32 internal constant _rewards2Span_    = 'rewards2Span';
	bytes32 internal constant _rewards2Begin_   = 'rewards2Begin';

	uint public lep;            // 1: linear, 2: exponential, 3: power
	uint public period;
	uint public begin;

    mapping (address => uint256) public paid;

    function __StakingPool_init(address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr
    ) public virtual initializer {
	    __Governable_init(_governor);
        __StakingRewards_init(_rewardsDistribution, _rewardsToken, _stakingToken);
        config[_ecoAddr_] = uint(_ecoAddr);
        config[_ecoRatio_] = 0.1 ether;
    }

    function notifyRewardBegin(uint _lep, uint _period, uint _span, uint _begin) virtual public governance updateReward(address(0)) {
        lep             = _lep;         // 1: linear, 2: exponential, 3: power
        period          = _period;
        rewardsDuration = _span;
        begin           = _begin;
        periodFinish    = _begin.add(_span);
    }
    
    function notifyReward2(address _rewards2Token, uint _ratio, /*uint _span,*/ uint _begin) virtual external governance updateReward(address(0)) {
        config[_rewards2Token_] = uint(_rewards2Token);
        config[_rewards2Ratio_] = _ratio;
        //config[_rewards2Span_]  = _span;
        config[_rewards2Begin_] = _begin;
    }

    function rewardDelta() public view returns (uint amt) {
        if(begin == 0 || begin >= now || lastUpdateTime >= now)
            return 0;
            
        amt = rewardsToken.allowance(rewardsDistribution, address(this)).sub0(rewards[address(0)]);
        
        // calc rewardDelta in period
        if(lep == 3) {                                                              // power
            uint y = period.mul(1 ether).div(lastUpdateTime.add(rewardsDuration).sub(begin));
            uint amt1 = amt.mul(1 ether).div(y);
            uint amt2 = amt1.mul(period).div(now.add(rewardsDuration).sub(begin));
            amt = amt.sub(amt2);
        } else if(lep == 2) {                                                       // exponential
            if(now.sub(lastUpdateTime) < rewardsDuration)
                amt = amt.mul(now.sub(lastUpdateTime)).div(rewardsDuration);
        }else if(now < periodFinish)                                                // linear
            amt = amt.mul(now.sub(lastUpdateTime)).div(periodFinish.sub(lastUpdateTime));
        else if(lastUpdateTime >= periodFinish)
            amt = 0;
    }
    
    function rewardPerToken() virtual override public view returns (uint256) {
        if (_totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored.add(
                rewardDelta().mul(1e18).div(_totalSupply)
            );
    }

    modifier updateReward(address account) virtual override {
        (uint delta, uint d) = (rewardDelta(), 0);
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = now;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }

        address addr = address(config[_ecoAddr_]);
        uint ratio = config[_ecoRatio_];
        if(addr != address(0) && ratio != 0) {
            d = delta.mul(ratio).div(1 ether);
            rewards[addr] = rewards[addr].add(d);
        }
        rewards[address(0)] = rewards[address(0)].add(delta).add(d);
        _;
    }

    function getReward() virtual override public {
        getReward(msg.sender);
    }
    function getReward(address acct) virtual public {
        _getReward(acct);
    }
    function _getReward(address acct) virtual override internal nonReentrant updateReward(acct) {
        require(acct != address(0), 'invalid address');
        require(getConfig(_blocklist_, acct) == 0, 'In blocklist');
        bool isContract = acct.isContract();
        require(!isContract || config[_allowContract_] != 0 || getConfig(_allowlist_, acct) != 0, 'No allowContract');

        uint256 reward = rewards[acct];
        if (reward > 0) {
            paid[acct] = paid[acct].add(reward);
            paid[address(0)] = paid[address(0)].add(reward);
            rewards[acct] = 0;
            rewards[address(0)] = rewards[address(0)].sub0(reward);
            rewardsToken.safeTransferFrom(rewardsDistribution, acct, reward);
            emit RewardPaid(acct, reward);
            
            if(config[_rewards2Token_] != 0 && config[_rewards2Begin_] <= now) {
                uint reward2 = Math.min(reward.mul(config[_rewards2Ratio_]).div(1e18), IERC20(config[_rewards2Token_]).balanceOf(address(this)));
                IERC20(config[_rewards2Token_]).safeTransfer(acct, reward2);
                emit RewardPaid2(acct, reward2);
            }
        }
    }
    event RewardPaid2(address indexed user, uint256 reward2);

    function getRewardForDuration() override external view returns (uint256) {
        return rewardsToken.allowance(rewardsDistribution, address(this)).sub0(rewards[address(0)]);
    }
    
    function rewards2Token() virtual external view returns (address) {
        return address(config[_rewards2Token_]);
    }
    
    function rewards2Ratio() virtual external view returns (uint) {
        return config[_rewards2Ratio_];
    }
}

interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint) external;
}

contract EthPool is StakingPool {
    function stakeEth() virtual public payable {
        _stakeEth(msg.sender);
    }
    function _stakeEth(address acct) virtual internal nonReentrant updateReward(acct) {
        uint amount = msg.value;
        require(amount > 0, "Cannot stake 0");
        _totalSupply = _totalSupply.add(amount);
        _balances[acct] = _balances[acct].add(amount);
        IWETH(address(stakingToken)).deposit{value: amount}();                   //stakingToken.safeTransferFrom(acct, address(this), amount);
        emit Staked(acct, amount);
    }

    function withdrawEth(uint256 amount) virtual public {
        _withdrawEth(msg.sender, amount);
    }
    function _withdrawEth(address payable acct, uint256 amount) virtual internal nonReentrant updateReward(acct) {
        require(amount > 0, "Cannot withdraw 0");
        _totalSupply = _totalSupply.sub(amount);
        _balances[acct] = _balances[acct].sub(amount);
        IWETH(address(stakingToken)).withdraw(amount);                           //stakingToken.safeTransfer(acct, amount);
        acct.transfer(amount);
        emit Withdrawn(acct, amount);
    }

    function exitEth() virtual public {
        _exitEth(msg.sender);
    }
    function _exitEth(address payable acct) virtual internal {
        _getReward(acct);
        _withdrawEth(acct, _balances[acct]);
    }
    
    receive () payable external {
        
    }
}

contract LimitPool is EthPool {
    Refer public refer;
    address public currency;
    uint public limit;

    function __LimitPool_init(address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr,
        address _refer,
        address _currency,
        uint _limit
    ) public virtual initializer {
        __StakingPool_init(_governor, _rewardsDistribution, _rewardsToken, _stakingToken, _ecoAddr);
        refer = Refer(_refer);
        currency = _currency;
        limit = _limit;
    }

    function calcStakeVol() virtual public view returns (uint) {
        if(currency == address(stakingToken))
            return limit;
        IUniswapV2Factory factory = IUniswapV2Factory(IUniswapV2Router02(refer.router()).factory());
        require(factory.getPair(currency, address(stakingToken)) != address(0), 'Not exist pair');
        (uint R1, uint R2) = UniswapV2Library.getReserves(address(factory), currency, address(stakingToken));
        return UniswapV2Library.quote(limit, R1, R2);
    }
    
    modifier checkLimit(address acct) {
        _;
        require(_balances[acct] <= calcStakeVol(), 'out of limit');
    }
    
    // comment for reduce code size
    //function stakeWithPermit(uint256 amount, uint deadline, uint8 v, bytes32 r, bytes32 s) virtual override public checkLimit(msg.sender) {
    //    super.stakeWithPermit(amount, deadline, v, r, s);
    //}

    function stake(uint256 amount) virtual override public checkLimit(msg.sender) {
        super.stake(amount);
    }
    
    function stakeEth() virtual override public payable checkLimit(msg.sender) {
        require(address(stakingToken) == refer.WHT(), 'stakingToken is not WHT');
        super.stakeEth();
    }
    
    function withdrawEth(uint256 amount) virtual override public {
        require(address(stakingToken) == refer.WHT(), 'stakingToken is not WHT');
        super.withdrawEth(amount);
    }
}

contract ReferPool is EthPool {
    bytes32 internal constant _stakingThreshold_        = 'stakingThreshold';
    bytes32 internal constant _refererWeight_           = 'refererWeight';
    
    Refer public refer;
    uint256 public referTotalSupply;
    mapping (address => uint256) public referBalanceOf;
    mapping (address => uint256) public referRewards;
    mapping (address => uint256) public referPaid;

    function __ReferPool_init(
        address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr,
        address _refer
    ) public virtual initializer {
        __StakingPool_init(_governor, _rewardsDistribution, _rewardsToken, _stakingToken, _ecoAddr);
        __ReferPool_init_unchained(_refer);
    }
    
    function __ReferPool_init_unchained(address _refer) public governance {
        refer = Refer(_refer);
        config[_stakingThreshold_] = 100    ether;
        _setConfig(_refererWeight_, 1, 0.25 ether);
        _setConfig(_refererWeight_, 2, 0.10 ether);
    }
    
    function totalSupplySum() virtual public view returns (uint) {
        return _totalSupply.add(referTotalSupply);
    }

    function balanceSumOf(address acct) virtual public view returns (uint) {
        return _balances[acct].add(referBalanceOf[acct]);
    }
    
    function _increaseBalanceRefer(address referee, uint increasement) internal {
        address referer  = refer.refererOf(referee);
        address referer2 = refer.refererOf(referer);
        uint inc1 = refer.balanceOf(referer)  != 0 ? increasement.mul(getConfig(_refererWeight_, 1)).div(1 ether) : 0;
        uint inc2 = refer.balanceOf(referer2) != 0 ? increasement.mul(getConfig(_refererWeight_, 2)).div(1 ether) : 0;
        referBalanceOf[referer]  = referBalanceOf[referer ].add(inc1);
        referBalanceOf[referer2] = referBalanceOf[referer2].add(inc2);
        referTotalSupply        = referTotalSupply.add(inc1).add(inc2); 
    }
    
    function _decreaseBalanceRefer(address referee, uint decreasement) internal {
        address referer  = refer.refererOf(referee);
        address referer2 = refer.refererOf(referer);
        uint dec1 = refer.balanceOf(referer)   != 0 ? decreasement.mul(getConfig(_refererWeight_, 1)).div(1 ether) : 0;
        uint dec2 = refer.balanceOf(referer2)  != 0 ? decreasement.mul(getConfig(_refererWeight_, 2)).div(1 ether) : 0;
        referBalanceOf[referer]  = referBalanceOf[referer ].sub0(dec1);
        referBalanceOf[referer2] = referBalanceOf[referer2].sub0(dec2);
        referTotalSupply         = referTotalSupply.sub0(dec1).sub0(dec2); 
    }
    
    // comment for reduce code size
    //function stakeWithPermit(uint256 amount, uint deadline, uint8 v, bytes32 r, bytes32 s) virtual override public checkRefer(msg.sender) {
    //    super.stakeWithPermit(amount, deadline, v, r, s);
    //    _increaseBalanceRefer(msg.sender, amount);
    //}

    function _stake(address acct, uint256 amount) virtual override internal checkRefer(acct) {
        super._stake(acct, amount);
        _increaseBalanceRefer(acct, amount);
    }

    function _stakeEth(address acct) virtual override internal checkRefer(acct) {
        require(address(stakingToken) == refer.WHT(), 'stakingToken is not WHT');
        super._stakeEth(acct);
        _increaseBalanceRefer(acct, msg.value);
    }
    
    function _withdraw(address acct, uint256 amount) virtual override internal {
        super._withdraw(acct, amount);
        _decreaseBalanceRefer(acct, amount);
    }
    
    function _withdrawEth(address payable acct, uint256 amount) virtual override internal {
        require(address(stakingToken) == refer.WHT(), 'stakingToken is not WHT');
        super._withdrawEth(acct, amount);
        _decreaseBalanceRefer(acct, amount);
    }
    
    modifier checkRefer(address acct) {
        require(refer.refererOf(acct) != address(0), 'Bind referer first');
        _;
    }
    
    function rewardPerToken() override public view returns (uint256) {
        if (_totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored.add(
                rewardDelta().mul(1e18).div(totalSupplySum())
            );
    }

    function referEarned(address acct) virtual public view returns (uint) {
        return referBalanceOf[acct].mul(rewardPerToken().sub(userRewardPerTokenPaid[acct])).div(1e18).add(referRewards[acct]);
    }

    //function earned(address acct) virtual override public view returns (uint) {
    //    return super.earned(acct).add(referEarned(acct));
    //}

    modifier updateReward(address acct) virtual override {
        (uint delta, uint d) = (rewardDelta(), 0);

        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = now;
        if (acct != address(0)) {
            _updateReward(acct);
            _updateReward(acct = refer.refererOf(acct));
            _updateReward(refer.refererOf(acct));
        }

        address addr = address(config[_ecoAddr_]);
        uint ratio = config[_ecoRatio_];
        if(addr != address(0) && ratio != 0) {
            d = delta.mul(ratio).div(1 ether);
            rewards[addr] = rewards[addr].add(d);
        }
        rewards[address(0)] = rewards[address(0)].add(delta).add(d);

        _;
    }
    
    function _updateReward(address acct) virtual internal {
        rewards[acct] = earned(acct);
        referRewards[acct] = referEarned(acct);
        userRewardPerTokenPaid[acct] = rewardPerTokenStored;
    }
    
    //function getReward(address acct) virtual override public {
    //    super.getReward(acct);
    //    referPaid[acct] = referPaid[acct].add(referRewards[acct]);
    //    referRewards[acct] = 0;
    //}

    function getReferReward() virtual public {
        getReferReward(msg.sender);
    }
    function getReferReward(address acct) virtual public {
        _getReferReward(acct);
    }
    function _getReferReward(address acct) virtual internal nonReentrant updateReward(acct) {
        require(acct != address(0), 'invalid address');
        require(getConfig(_blocklist_, acct) == 0, 'In blocklist');
        bool isContract = acct.isContract();
        require(!isContract || config[_allowContract_] != 0 || getConfig(_allowlist_, acct) != 0, 'No allowContract');

        uint256 reward = referRewards[acct];
        if (reward > 0) {
            referPaid[acct] = referPaid[acct].add(reward);
            referPaid[address(0)] = referPaid[address(0)].add(reward);
            referRewards[acct] = 0;
            rewards[address(0)] = rewards[address(0)].sub0(reward);
            rewardsToken.safeTransferFrom(rewardsDistribution, acct, reward);
            emit ReferRewardPaid(acct, reward);
            
            if(config[_rewards2Token_] != 0 && config[_rewards2Begin_] <= now) {
                uint reward2 = Math.min(reward.mul(config[_rewards2Ratio_]).div(1e18), IERC20(config[_rewards2Token_]).balanceOf(address(this)));
                IERC20(config[_rewards2Token_]).safeTransfer(acct, reward2);
                emit ReferRewardPaid2(acct, reward2);
            }
        }
    }
    event ReferRewardPaid(address indexed user, uint256 reward);
    event ReferRewardPaid2(address indexed user, uint256 reward2);
}

contract ThresholdPool is ReferPool {
    address public currency;
    uint public threshold;
    mapping (address => bool) public eligible;

    function __ThresholdPool_init(address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr,
        address _refer,
        address _currency,
        uint _threshold
    ) public virtual initializer {
        __ReferPool_init(_governor, _rewardsDistribution, _rewardsToken, _stakingToken, _ecoAddr, _refer);
        __ThresholdPool_init_unchained(_currency, _threshold);
    }
    
    function __ThresholdPool_init_unchained(address _currency, uint _threshold) public governance {
        currency = _currency;
        threshold = _threshold;
    }

    function lptNetValue(uint vol) public view returns (uint) {
        if(vol == 0)
            return 0;
        IUniswapV2Router02 router = IUniswapV2Router02(refer.router());
        address WHT = refer.WHT();
        uint wht = IERC20(WHT).balanceOf(address(stakingToken));
        if(wht > 0) {
            return wht.mul(vol).div(IERC20(stakingToken).totalSupply()).mul(2);
        } else {
            uint gtl = IERC20(rewardsToken).balanceOf(address(stakingToken));
            //require(cir > 0);
            gtl = gtl.mul(vol).div(IERC20(stakingToken).totalSupply()).mul(2);
            (uint reserve0, uint reserve1,) = IUniswapV2Pair(IUniswapV2Factory(router.factory()).getPair(WHT, address(rewardsToken))).getReserves();
            //(reserve0, reserve1) = tokenA == WHT < rewardsToken ? (reserve0, reserve1) : (reserve1, reserve0);
            return WHT < address(rewardsToken) ? gtl.mul(reserve0) / reserve1 : gtl.mul(reserve1) / reserve0;
        }
    }

    modifier updateEligible(address acct) {
        _;
        eligible[acct] = lptNetValue(_balances[acct]) >= threshold;
    }
    
    // comment for reduce code size
    //function stakeWithPermit(uint256 amount, uint deadline, uint8 v, bytes32 r, bytes32 s) virtual override public updateEligible(msg.sender) {
    //    super.stakeWithPermit(amount, deadline, v, r, s);
    //}

    function stake(uint256 amount) virtual override public updateEligible(msg.sender) {
        super.stake(amount);
    }

    function withdraw(uint256 amount) virtual override public updateEligible(msg.sender) {
        super.withdraw(amount);
    }

    function referEarned(address acct) virtual override public view returns (uint) {
        if(eligible[acct])
            return super.referEarned(acct);
        else
            return 0;
    }
    
    function earned(address account) virtual override public view returns (uint256) {
        if(eligible[account])
            return super.earned(account);
        else
            return 0;
    }
}

contract TermPool is ReferPool {
    bytes32 internal constant _stakingTerm_             = 'stakingTerm';
    bytes32 internal constant _gradeVol_                = 'gradeVol';
    
    mapping(address => uint[]) public orderBalanceOf;
    mapping(address => uint[]) public orderTimestampOf;
    mapping(address => uint[]) public orderRewardPerTokenOf;
    mapping(address => uint[]) public orderPaid;

    function orderCount(address acct) virtual public view returns (uint) {
        return orderBalanceOf[acct].length;
    }
    
    function __TermPool_init(
        address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr,
        address _refer
    ) public virtual initializer {
        __ReferPool_init(_governor, _rewardsDistribution, _rewardsToken, _stakingToken, _ecoAddr, _refer);
        __TermPool_init_unchained();
    }
    
    function __TermPool_init_unchained() public governance {
        config[_stakingTerm_] = 5 minutes;         //5 days;   //todo
        _setConfig(_gradeVol_,  1,  100 ether);
        _setConfig(_gradeVol_,  2, 1000 ether);
        _setConfig(_gradeVol_,  3,10000 ether);
        _setConfig(_gradeVol_, 11,   80 ether);
        _setConfig(_gradeVol_, 12,   20 ether);
        _setConfig(_gradeVol_, 21,  800 ether);
        _setConfig(_gradeVol_, 22,  200 ether);
        _setConfig(_gradeVol_, 31, 8000 ether);
        _setConfig(_gradeVol_, 32, 2000 ether);
    }
    
    function calcStakeVol(uint256 grade) virtual public view returns (uint) {
        address usd = Refer(refer).usd();
        if(usd == address(stakingToken))
            return getConfig(_gradeVol_, grade);
        IUniswapV2Factory factory = IUniswapV2Factory(IUniswapV2Router02(refer.router()).factory());
        require(factory.getPair(usd, address(stakingToken)) != address(0), 'Not exist pair');
        (uint R1, uint R2) = UniswapV2Library.getReserves(address(factory), usd, address(stakingToken));
        return UniswapV2Library.quote(getConfig(_gradeVol_, grade), R1, R2);
    }
    
    function stake(uint256 grade) virtual override public {
        _stake(msg.sender, grade);
    }
    function _stake(address acct, uint256 grade) virtual override internal {
        uint vol = calcStakeVol(grade);
        super._stake(acct, vol);
        _newOrder(acct, vol);
    }
    
    function stakeEth() virtual override public payable {
        revert('instead of stakeEth(uint256 grade)');
    }
    function stakeEth(uint256 grade) virtual public payable {
        _stakeEth(msg.sender, grade);
    }
    function _stakeEth(address acct, uint256 grade) virtual internal {
        uint vol = calcStakeVol(grade);
        require(msg.value >= vol, 'msg.value is not enough');
        super._stakeEth(acct);
        _newOrder(acct, msg.value);
    }
    
    function _newOrder(address acct, uint vol) virtual internal {
        orderBalanceOf[acct].push(vol);
        orderTimestampOf[acct].push(now);
        orderRewardPerTokenOf[acct].push(rewardPerTokenStored);
        orderPaid[acct].push(0);
    }

    function withdraw(uint256 index) virtual override public {
        _withdraw(msg.sender, index);
    }
    function withdraw(address acct, uint256 index) virtual external governance {
        _withdraw(acct, index);
    }
    function _withdraw(address acct, uint256 index) virtual override internal {
        require(orderRewardPerTokenOf[acct][index] != uint(-1), 'withdrawal already.');
        require(now >= orderTimestampOf[acct][index].add(config[_stakingTerm_]), 'Not yet due.');
        if(address(stakingToken) == refer.WHT())
            super._withdrawEth(address(uint160(acct)), orderBalanceOf[acct][index]);
        else
            super._withdraw(acct, orderBalanceOf[acct][index]);
        
        _getOrderReward(acct, index);
        orderRewardPerTokenOf[acct][index] = uint(-1);
    }
    function _withdrawEth(address payable acct, uint index) virtual override internal {
        _withdraw(acct, index);
    }
    function withdrawEth(uint256 index) virtual override public {
        _withdraw(msg.sender, index);
    }
    
    function _getOrderReward(address acct, uint index) virtual internal {
        (uint rwd, uint reward) = orderEarned(acct, index);
        orderPaid[acct][index] = orderPaid[acct][index].add(rwd);
        paid[acct] = paid[acct].add(rwd);
        rewardsToken.safeTransferFrom(rewardsDistribution, acct, rwd);
        emit RewardPaid(acct, rwd);
        
        address referer = refer.refererOf(acct);
        uint r1 = _getReferReward(referer, rwd, reward, getConfig(_refererWeight_, 1));
        
        address referer2 = refer.refererOf(referer);
        uint r2 = _getReferReward(referer2, rwd, reward, getConfig(_refererWeight_, 2));

        paid[address(0)] = paid[address(0)].add(rwd).add(r1).add(r2);
    }
    
    function _getReferReward(address referer, uint rwd, uint reward, uint weight) virtual internal updateReward(referer) returns (uint r) {
        r = rwd.mul(weight).div(1e18);
        paid[referer] = paid[referer].add(r);
        referPaid[referer] = referPaid[referer].add(r);
        referRewards[referer] = referRewards[referer].sub0(reward.mul(weight).div(1e18));
        rewardsToken.safeTransferFrom(rewardsDistribution, referer, r);
        emit ReferRewardPaid(referer, r);
    }
    event ReferRewardPaid(address indexed referer, uint r);
    
    function _getReferReward(address acct) virtual override internal {
        getReward(acct);
    }
    
    function getReward(address) virtual override public {
        revert('No getReward separately, but withdraw or exit.');
    }
    
    function _exit(address acct) virtual override internal {
        for(uint i=0; i<orderBalanceOf[acct].length; i++)
            _withdraw(acct, i);
    }

    function orderEarned(address acct, uint index) virtual public view returns (uint rwd, uint reward) {
        rwd = reward = orderBalanceOf[acct][index].mul(rewardPerToken().sub(orderRewardPerTokenOf[acct][index])).div(1e18);
        if(config[_stakingTerm_] < now.sub(orderTimestampOf[acct][index]))
            rwd = reward.mul(config[_stakingTerm_]).div(now.sub(orderTimestampOf[acct][index]));
    }

}

contract TermPoolInner is TermPool {
    address public caller;
    
    function __TermPoolInner_init(
        address _governor, 
        address _rewardsDistribution,
        address _rewardsToken,
        address _stakingToken,
        address _ecoAddr,
        address _refer,
        address _caller
    ) public virtual initializer {
        __TermPool_init(_governor, _rewardsDistribution, _rewardsToken, _stakingToken, _ecoAddr, _refer);
        __TermPoolInner_init_unchained(_caller);
    }
    
    function __TermPoolInner_init_unchained(address _caller) public governance {
        caller = _caller;
    }
    
    modifier denyCall {
        _;
        revert('deny call');
    }
    function stake(uint256 grade) virtual override public denyCall {
    }
    function stakeEth(uint256 grade) virtual override public payable denyCall {
    }
    function withdraw(uint256 index) virtual override public denyCall {
    }
    function withdrawEth(uint256 index) virtual override public denyCall {
    }

    modifier onlyCaller {
        require(msg.sender == caller, 'only called by caller');
        _;
    }
    
    function stake_(address acct, uint256 grade) virtual public onlyCaller {
        _stake(acct, grade);
    }
    function stakeEth_(address acct, uint256 grade) virtual public payable onlyCaller {
        _stakeEth(acct, grade);
    }
    
    function withdraw_(address acct, uint256 index) virtual public onlyCaller {
        _withdraw(acct, index);
    }
    function withdrawEth_(address payable acct, uint256 index) virtual public onlyCaller {
        _withdrawEth(acct, index);
    }
    
    function exit_(address payable acct) virtual public onlyCaller {
        _exit(acct);
    }
}

contract DualPool is Configurable {
    using SafeMath for uint;
    using SafeERC20 for IERC20;
    
    TermPoolInner public pool1;
    TermPoolInner public pool2;
    
    function __DualPool_init(
        address _governor, 
        address payable _pool1,
        address payable _pool2
    ) public virtual initializer {
	    __Governable_init(_governor);
        __DualPool_init_unchained(_pool1, _pool2);
    }
    
    function __DualPool_init_unchained(address payable _pool1, address payable _pool2) public governance {
        pool1 = TermPoolInner(_pool1);         TermPoolInner(_pool1).caller();     // just test
        pool2 = TermPoolInner(_pool2);         TermPoolInner(_pool2).caller();     // just test
    }
    
    function calcStakeVol(uint256 grade) virtual public view returns (uint vol1, uint vol2) {
        vol1 = pool1.calcStakeVol(grade * 10 + 1);
        vol2 = pool2.calcStakeVol(grade * 10 + 2);
    }
    
    function stake(uint256 grade) virtual public payable {
        if(msg.value > 0 && address(pool1.stakingToken()) == pool1.refer().WHT())
            pool1.stakeEth_{value: msg.value}(msg.sender, grade * 10 + 1);
        else
            pool1.stake_(msg.sender, grade * 10 + 1);
        pool2.stake_(msg.sender, grade * 10 + 2);
    }
    
    function withdraw(uint256 index) virtual public {
        pool1.withdraw_(msg.sender, index);
        pool2.withdraw_(msg.sender, index);
    }
    function withdraw(address acct, uint256 index) virtual external governance {
        pool1.withdraw_(acct, index);
        pool2.withdraw_(acct, index);
    }

    function exit() virtual public {
        pool1.exit_(msg.sender);
        pool2.exit_(msg.sender);
    }

    function totalSupply() virtual public view returns (uint) {
        return pool1.totalSupply().add(pool2.totalSupply());
    }
    function totalSupplySum()  virtual public view returns (uint) {
        return pool1.totalSupplySum().add(pool2.totalSupplySum());
    }
    
    function balanceOf(address acct) virtual public view returns (uint b1, uint b2) {
        b1 = pool1.balanceOf(acct);
        b2 = pool2.balanceOf(acct);
    }
    
    function earned(address acct) virtual public view returns (uint) {
        return pool1.earned(acct).add(pool2.earned(acct));
    }
    
    function paid(address acct) virtual public view returns (uint) {
        return pool1.paid(acct).add(pool2.paid(acct));
    }
    
    function referBalanceOf(address acct) virtual public view returns (uint b1, uint b2) {
        b1 = pool1.referBalanceOf(acct);
        b2 = pool2.referBalanceOf(acct);
    }
    
    function referEarned(address acct) virtual public view returns (uint) {
        return pool1.referEarned(acct).add(pool2.referEarned(acct));
    }
    
    function referPaid(address acct) virtual public view returns (uint) {
        return pool1.referPaid(acct).add(pool2.referPaid(acct));
    }
    
    function orderCount(address acct) virtual public view returns (uint) {
        return pool1.orderCount(acct);
    }
    
    function orderBalanceOf(address acct, uint index) virtual public view returns (uint b1, uint b2) {
        b1 = pool1.orderBalanceOf(acct, index);
        b2 = pool2.orderBalanceOf(acct, index);
    }
    
    function orderEarned(address acct, uint index) virtual public view returns (uint rwd, uint reward) {
        (uint rwd1, uint reward1) = pool1.orderEarned(acct, index);
        (uint rwd2, uint reward2) = pool2.orderEarned(acct, index);
        return (rwd1.add(rwd2), reward1.add(reward2));
    }
    
    function orderPaid(address acct, uint index) virtual public view returns (uint) {
        return pool1.orderPaid(acct, index).add(pool2.orderPaid(acct, index));
    }
    
}


contract Refer is Configurable {
    using SafeMath for uint;
    
    bytes32 internal constant _refererWeight_           = 'refererWeight';

    mapping (address => address) public refererOf;          // acct => referer;
    mapping (address => uint) public refereeN;
    mapping (address => uint) public referee2N;
    address payable[] public pools;
    address public router;
    address public usd;
    
   function ___referinit(address governor, address top, address router_, address usd_) public initializer {
        __Governable_init(governor);
        ___refer_init_unchained(top, router_, usd_);
    }
    
    function ___refer_init_unchained(address top, address router_, address usd_) public governance {
        _setConfig(_refererWeight_, 1, 0.25 ether);
        _setConfig(_refererWeight_, 2, 0.10 ether);

        refererOf[top] = top;
        router = router_;
        usd = usd_;
    }
    
    function WETH() public view returns (address addr) {
        return WHT();
    }
    function WHT() public view returns (address addr) {
        uint id;
        assembly {
            id := chainid()
        }
        if(id == 128)
            return IUniswapV2Router02(router).WHT();
        else
            return IUniswapV2Router02(router).WETH();

        //assembly {
        //    switch chainid() 
        //        case  1  { addr := 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 }      // Ethereum Mainnet
        //        case  3  { addr := 0xc778417E063141139Fce010982780140Aa0cD5Ab }      // Ethereum Testnet Ropsten
        //        case  4  { addr := 0xc778417E063141139Fce010982780140Aa0cD5Ab }      // Ethereum Testnet Rinkeby
        //        case  5  { addr := 0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6 }      // Ethereum Testnet Gorli
        //        case 42  { addr := 0xd0A1E359811322d97991E03f863a0C30C2cF029C }      // Ethereum Testnet Kovan
        //        case 128 { addr := 0x5545153ccfca01fbd7dd11c0b23ba694d9509a6f }      // HECO Mainnet
        //        default  { addr := 0x0                                        }      // unknown 
        //}
    }
    
    function bind(address referer) virtual public {
        require(refererOf[msg.sender] == address(0), 'Already binded');
        require(refererOf[referer] != address(0), 'referer has not binded yet');
        require(referer != msg.sender && refererOf[referer] != msg.sender && refererOf[refererOf[referer]] != msg.sender, 'No bind cyclic');
        refererOf[msg.sender] = referer;
        
        refereeN[referer] = refereeN[referer].add(1);
        referee2N[refererOf[referer]] = referee2N[refererOf[referer]].add(1);
        emit Bind(msg.sender, referer, refererOf[referer]);
    }
    event Bind(address indexed referee, address indexed referer, address indexed referer2);

    function poolN() external view returns (uint) {
        return pools.length;
    }

    function addPool(address payable pool) virtual external governance {
        //ReferPool(pool).refer();      // just check
        pools.push(pool);
    }
    
    function referBalanceOf(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(ReferPool(pools[i]).referBalanceOf(acct));
    }
    function referEarned(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(ReferPool(pools[i]).referEarned(acct));
    }
    function referPaid(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(ReferPool(pools[i]).referPaid(acct));
    }
    
    function balanceOf(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(StakingPool(pools[i]).balanceOf(acct));
    }
    function earned(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(StakingPool(pools[i]).earned(acct));
    }
    function paid(address acct) external view returns (uint amt) {
        for(uint i=0; i<pools.length; i++)
            amt = amt.add(StakingPool(pools[i]).paid(acct));
    }
    function getReward() external {
        getReward(msg.sender);
    }
    function getReward(address payable acct) public {
        for(uint i=0; i<pools.length; i++)
            StakingPool(pools[i]).getReward(acct);
    }

}


contract Mine is Governable {
    address public reward;

    function __Mine_init(address governor, address reward_) public initializer {
        __Governable_init(governor);
        reward = reward_;
    }
    
    function approvePool(address pool, uint amount) public governance {
        IERC20(reward).approve(pool, amount);
    }
    
}


contract GTL is ERC20UpgradeSafe, Configurable {
    address vault;

	function __GTL_init(address governor, address mine, address eco) public initializer {
		__Governable_init(governor);
		__ERC20_init("Gatling Finance Governance Token", "GTL");
		
		uint8 decimals = 18;
		_setupDecimals(decimals);
		
		_mint(mine, 9300_000 * 10 ** uint256(decimals));
		_mint(eco,   700_000 * 10 ** uint256(decimals));       // 50k for initial liquidity, 20k for airdrop to channel
	}
	
}

