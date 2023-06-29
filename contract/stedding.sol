// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Stedding is ChainlinkClient, Ownable, ReentrancyGuard {
    using Chainlink for Chainlink.Request;

    uint256 oraclePayment;
    bytes32 jobId;
    // This array will keep track of all entries for iteration
    string[] public entryKeys;
    // Add this state variable
bool public initialRootDomainSet = false;

    struct Entry {
        string entry;
        string rootDomain;
        string comment;
        bool isVerified;
    }

    struct DnsVerificationRequest {
        string entry;
        address sender;
    }

    address[] public rootDomainOwners;
    mapping(address => bool) public isRootDomainOwner;
    mapping(string => Entry) public allowList;
    mapping(bytes32 => string) public requestIdToEntry;
    mapping(string => bool) public isValidRootDomain;
    mapping(bytes32 => DnsVerificationRequest) public dnsVerificationRequests;

    event EntryAdded(string entry, string comment);
    event EntryUpdated(string entry, string newComment);
    event EntryVerified(string entry);
    event EntryVerificationSucceeded(string entry);
    event EntryVerificationFailed(string entry, string reason);
    event RootDomainRemoved(string rootDomain);

    constructor() Ownable() {
        setChainlinkToken(0x326C977E6efc84E512bB9C30f76E30c160eD06FB);
        setChainlinkOracle(0xB9756312523826A566e222a34793E414A81c88E1);
        jobId = "791bd73c8a1349859f09b1cb87304f71";
        oraclePayment = 0.1 * 10 ** 18;
        rootDomainOwners.push(msg.sender);
        isRootDomainOwner[msg.sender] = true;
    }

    // Function to set the initial root domain
function setInitialRootDomain(string memory rootDomain) external onlyOwner {
    require(!initialRootDomainSet, "Initial root domain already set");
    isValidRootDomain[rootDomain] = true;
    initialRootDomainSet = true;
}

// Function to add more root domains
function addRootDomain(string memory rootDomain) external onlyOwner {
    require(initialRootDomainSet, "Initial root domain must be set first");
    isValidRootDomain[rootDomain] = true;
}

    function addressToString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    function requestDnsVerification(string memory entry, string memory rootDomain, address sender) internal {
        Chainlink.Request memory req = buildChainlinkRequest(jobId, address(this), this.dnsVerificationFulfillment.selector);
        req.add("name", rootDomain);
        req.add("record", addressToString(sender));
        bytes32 requestId = sendChainlinkRequest(req, oraclePayment);

        dnsVerificationRequests[requestId] = DnsVerificationRequest(entry, sender);
    }

    function dnsVerificationFulfillment(bytes32 _requestId, bool _isVerified) external nonReentrant recordChainlinkFulfillment(_requestId) {
        DnsVerificationRequest memory dnsRequest = dnsVerificationRequests[_requestId];

        if (_isVerified) {
            allowList[dnsRequest.entry].isVerified = true;
            emit EntryVerificationSucceeded(dnsRequest.entry);
        } else {
            emit EntryVerificationFailed(dnsRequest.entry, "DNS Verification Failed");
        }

        delete dnsVerificationRequests[_requestId];
    }

    function addEntry(
        string memory entry,
        string memory rootDomain,
        string memory comment
    ) public {
        require(allowList[entry].isVerified == false, "Entry already exists");
        require(isValidRootDomain[rootDomain], "Invalid root domain");
        allowList[entry] = Entry(entry, rootDomain, comment, false);
        entryKeys.push(entry);  // Store the key
        requestDnsVerification(entry, rootDomain, msg.sender);
        emit EntryAdded(entry, comment);
    }

    function updateEntry(
        string memory entry,
        string memory rootDomain,
        string memory newComment
    ) public {
        require(allowList[entry].isVerified, "Entry does not exist");
        require(isValidRootDomain[rootDomain], "Invalid root domain");

        string memory existingRootDomain = allowList[entry].rootDomain;
        require(
            keccak256(abi.encodePacked(existingRootDomain)) ==
                keccak256(abi.encodePacked(rootDomain)),
            "Root domain mismatch"
        );

        allowList[entry].isVerified = false;
        allowList[entry].comment = newComment;
        requestDnsVerification(entry, rootDomain, msg.sender);

        emit EntryUpdated(entry, newComment);
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
}
