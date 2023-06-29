// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";

/**
 * @title Stedding
 * @dev Allows approved web3 projects to add URLs and domains to an on-chain allowlist. 
 * Projects must be verified via off-chain DNS lookup against the sender's address.
 */
contract Stedding is ChainlinkClient, Ownable, ReentrancyGuard {
    using Chainlink for Chainlink.Request;

    uint256 public oraclePayment;
    bytes32 public jobId;
    uint256 public projectDomainCount;
    address public linkTokenAddress;
    string[] public entryKeys;

    // Struct representing an entry in the allowlist
    struct Entry {
        string entry;
        string projectDomain;
        string comment;
        bool isVerified;
        address verifiedAddress; // The address that was verified for this entry
    }

    // Struct representing a DNS verification request
    struct DNSVerificationRequest {
        string entry;
        address sender;
        string newComment;
    }

    mapping(string => Entry) public allowList;
    mapping(bytes32 => string) public requestIdToEntry;
    mapping(string => bool) public isValidProjectDomain;
    mapping(bytes32 => DNSVerificationRequest) public dnsVerificationRequests;

    event EntryAdded(bytes32 indexed requestId, string entry, string comment);
    event EntryUpdated(string entry, string newComment);
    event EntryVerificationSucceeded(string entry);
    event EntryVerificationFailed(string entry, string reason);
    event ProjectDomainAdded(string projectDomain);
    event ProjectDomainRemoved(string projectDomain);

    modifier validProjectDomain(string memory projectDomain) {
        require(isValidProjectDomain[projectDomain], "Invalid project domain");
        _;
    }

    constructor() Ownable() {
        address _linkTokenAddress = 0x326C977E6efc84E512bB9C30f76E30c160eD06FB; // TODO: make this a configurable parameter
        linkTokenAddress = _linkTokenAddress;
        setChainlinkToken(_linkTokenAddress);
        setChainlinkOracle(0xB9756312523826A566e222a34793E414A81c88E1);
        jobId = "791bd73c8a1349859f09b1cb87304f71";
        oraclePayment = 0.1 * 10 ** 18;
    }

    function setOraclePayment(uint256 newPayment) external onlyOwner {
        oraclePayment = newPayment;
    }

    function addProjectDomain(string memory projectDomain) external onlyOwner {
        isValidProjectDomain[projectDomain] = true;
        projectDomainCount++;
        emit ProjectDomainAdded(projectDomain);
    }

    function removeProjectDomain(string memory projectDomain) external onlyOwner {
        isValidProjectDomain[projectDomain] = false;
        projectDomainCount--;
        emit ProjectDomainRemoved(projectDomain);
    }

    function requestDNSVerification(
        string memory entry,
        string memory projectDomain,
        string memory newComment,
        address sender
    ) internal returns (bytes32 requestId) {
        Chainlink.Request memory req = buildChainlinkRequest(
            jobId,
            address(this),
            this.DNSVerificationFulfillment.selector
        );
        req.add("name", projectDomain);
        req.add("record", addressToString(sender));
        requestId = sendChainlinkRequest(req, oraclePayment);
        dnsVerificationRequests[requestId] = DNSVerificationRequest(
            entry,
            sender,
            newComment
        );
        return requestId;
    }

function DNSVerificationFulfillment(
    bytes32 _requestId,
    bool _isVerified
) external nonReentrant recordChainlinkFulfillment(_requestId) {
    DNSVerificationRequest memory dnsRequest = dnsVerificationRequests[
        _requestId
    ];

    if (_isVerified) {
        allowList[dnsRequest.entry].isVerified = true;
        allowList[dnsRequest.entry].verifiedAddress = dnsRequest.sender;
        emit EntryVerificationSucceeded(dnsRequest.entry);

        // Check if this is an update
        string memory entry = requestIdToEntry[_requestId];
        if (bytes(entry).length > 0) {
            // Use the newComment from the DNSVerificationRequest struct
            allowList[entry].comment = dnsRequest.newComment;
            emit EntryUpdated(entry, dnsRequest.newComment);
            delete requestIdToEntry[_requestId];
        }
    } else {
        emit EntryVerificationFailed(
            dnsRequest.entry,
            "DNS Verification Failed"
        );
    }

    delete dnsVerificationRequests[_requestId];
}



    function addEntry(
    string memory entry,
    string memory projectDomain,
    string memory comment
) public validProjectDomain(projectDomain) {
    require(!allowList[entry].isVerified, "Entry already exists");

    LinkTokenInterface(linkTokenAddress).transferFrom(
        msg.sender,
        address(this),
        oraclePayment
    );

    allowList[entry] = Entry(entry, projectDomain, comment, false, address(0));

    // Only add to entryKeys if this is the first time this entry is being added
    if (allowList[entry].verifiedAddress == address(0)) {
        entryKeys.push(entry);
    }

    bytes32 requestId = requestDNSVerification(
        entry,
        projectDomain,
        comment,
        msg.sender
    );
    emit EntryAdded(requestId, entry, comment);
}

function updateEntry(
    string memory entry,
    string memory projectDomain,
    string memory newComment
) public validProjectDomain(projectDomain) {
    require(allowList[entry].isVerified, "Entry does not exist");
    
    // Check if the sender is the same as the verified address for the entry
    // or if the address can be validated through a DNS lookup.
    bool isSameAddress = allowList[entry].verifiedAddress == msg.sender;

    if (!isSameAddress) {
        LinkTokenInterface(linkTokenAddress).transferFrom(
            msg.sender,
            address(this),
            oraclePayment
        );

        bytes32 requestId = requestDNSVerification(
            entry,
            projectDomain,
            newComment,
            msg.sender
        );
        
        // Store information for the verification in requestIdToEntry to be used in DNSVerificationFulfillment
        requestIdToEntry[requestId] = entry;
        
        // Store the new comment for the DNS verification
        dnsVerificationRequests[requestId].newComment = newComment;
    } else {
        string memory existingProjectDomain = allowList[entry].projectDomain;
        require(
            keccak256(abi.encodePacked(existingProjectDomain)) ==
                keccak256(abi.encodePacked(projectDomain)),
            "Project domain mismatch"
        );

        allowList[entry].comment = newComment;
        emit EntryUpdated(entry, newComment);
    }
}



    function getValidEntries() public view returns (string[] memory) {
    uint256 count = 0;

    // Count valid entries
    for (uint256 i = 0; i < entryKeys.length; i++) {
        string memory entry = entryKeys[i];
        if (allowList[entry].isVerified) {
            count++;
        }
    }

    string[] memory validEntries = new string[](count);
    uint256 index = 0;

    // Populate array with valid entries
    for (uint256 i = 0; i < entryKeys.length; i++) {
        string memory entry = entryKeys[i];
        if (allowList[entry].isVerified) {
            validEntries[index] = entry;
            index++;
        }
    }
    return validEntries;
}

    function addressToString(
        address _addr
    ) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }
}