// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";

contract ProofOfOwnership is ERC721, ERC721URIStorage, ERC721Enumerable, Ownable, AccessControl {
    using Counters for Counters.Counter;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");

    struct OwnershipHistory {
        address previousOwner;
        address newOwner;
        uint transferTimestamp;
    }

    struct TransferRequest {
        uint id;
        uint assetId;
        address requester;
        bool approved;
    }

    mapping(uint => OwnershipHistory[]) public ownershipHistories;
    mapping(uint => TransferRequest) public transferRequests;
    Counters.Counter private _requestIdCounter;

    event OwnershipTransferRequested(uint indexed requestId, uint indexed assetId, address indexed requester);
    event OwnershipTransferred(uint indexed assetId, address indexed previousOwner, address indexed newOwner, uint transferTimestamp);

    constructor() ERC721("ProofOfOwnership", "POO") {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _;
    }

    modifier onlyUser() {
        require(hasRole(USER_ROLE, msg.sender), "Caller is not a user");
        _;
    }

    function safeMint(
        address to,
        uint256 tokenId,
        string memory uri
    ) public onlyUser {
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function requestOwnershipTransfer(uint _assetId) public onlyUser {
        require(_exists(_assetId), "Invalid asset");

        _requestIdCounter.increment();
        uint newRequestId = _requestIdCounter.current();
        transferRequests[newRequestId] = TransferRequest(newRequestId, _assetId, msg.sender, false);

        emit OwnershipTransferRequested(newRequestId, _assetId, msg.sender);
    }

    function approveOwnershipTransfer(uint _requestId) public onlyUser {
        TransferRequest storage request = transferRequests[_requestId];
        require(_exists(request.assetId), "Invalid request");
        require(ownerOf(request.assetId) == msg.sender, "Only the owner can approve the transfer");
        require(!request.approved, "Request already approved");

        address previousOwner = ownerOf(request.assetId);
        _transfer(previousOwner, request.requester, request.assetId);
        request.approved = true;
        ownershipHistories[request.assetId].push(OwnershipHistory(previousOwner, request.requester, block.timestamp));

        emit OwnershipTransferred(request.assetId, previousOwner, request.requester, block.timestamp);
    }

    function verifyAsset(uint _assetId) public view returns (bool, address, string memory) {
        if (_exists(_assetId)) {
            return (true, ownerOf(_assetId), tokenURI(_assetId));
        }
        return (false, address(0), "");
    }

    function getOwnershipHistory(uint _assetId) public view returns (OwnershipHistory[] memory) {
        require(_exists(_assetId), "Invalid asset");
        return ownershipHistories[_assetId];
    }

    // Overrides required by Solidity for ERC721 and ERC721URIStorage
    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    // Overrides required by Solidity for ERC721Enumerable
    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize) internal override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721URIStorage, ERC721Enumerable, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
