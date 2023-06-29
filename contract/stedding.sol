// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";

contract Stedding is ChainlinkClient, Ownable, ReentrancyGuard {
    using Chainlink for Chainlink.Request;

    uint256 public oraclePayment;
    bytes32 public jobId;
    string[] public entryKeys;

    address public LINK_TOKEN_ADDRESS;

    enum ProposalType {
        Add,
        Remove
    }
    enum Vote {
        None,
        InFavor,
        Against
    }

    struct Proposal {
        ProposalType proposalType;
        string rootDomain;
        uint256 inFavor;
        uint256 against;
        mapping(string => Vote) votes; // map rootDomain to Vote
        bool resolved;
    }

    uint256 public rootDomainCount;
    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    // Events
    event ProposalCreated(
        uint256 proposalId,
        ProposalType proposalType,
        string rootDomain,
        string creator
    );
    event Voted(uint256 proposalId, string voterRootDomain, Vote vote);
    event ProposalResolved(uint256 proposalId, bool passed);

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

    mapping(string => Entry) public allowList;
    mapping(bytes32 => string) public requestIdToEntry;
    mapping(string => bool) public isValidRootDomain;
    mapping(bytes32 => DnsVerificationRequest) public dnsVerificationRequests;

    event EntryAdded(bytes32 indexed requestId, string entry, string comment);
    event EntryUpdated(string entry, string newComment);
    event EntryVerified(string entry);
    event EntryVerificationSucceeded(string entry);
    event EntryVerificationFailed(string entry, string reason);
    event RootDomainAdded(string rootDomain);
    event RootDomainRemoved(string rootDomain);

    modifier validRootDomain(string memory rootDomain) {
        require(isValidRootDomain[rootDomain], "Invalid root domain");
        _;
    }

    constructor() Ownable() {
        address _linkTokenAddress = 0x326C977E6efc84E512bB9C30f76E30c160eD06FB;
        LINK_TOKEN_ADDRESS = _linkTokenAddress;
        setChainlinkToken(_linkTokenAddress);
        setChainlinkOracle(0xB9756312523826A566e222a34793E414A81c88E1);
        jobId = "791bd73c8a1349859f09b1cb87304f71";
        oraclePayment = 0.1 * 10 ** 18;
    }

    function setOraclePayment(uint256 newPayment) external onlyOwner {
        oraclePayment = newPayment;
    }

    function addRootDomain(string memory rootDomain) public onlyOwner {
        require(bytes(rootDomain).length > 0, "Root domain cannot be empty");
        isValidRootDomain[rootDomain] = true;
        rootDomainCount++;
        emit RootDomainAdded(rootDomain);
    }

    function removeRootDomain(string memory rootDomain) public onlyOwner {
        require(bytes(rootDomain).length > 0, "Root domain cannot be empty");
        isValidRootDomain[rootDomain] = false;
        rootDomainCount--;
        emit RootDomainRemoved(rootDomain);
    }

    function createProposal(ProposalType proposalType, string memory rootDomain)
    external
    validRootDomain(rootDomain)
{
    require(bytes(rootDomain).length > 0, "Root domain cannot be empty");

    proposalCount++;

    Proposal storage newProposal = proposals[proposalCount];
    newProposal.proposalType = proposalType;
    newProposal.rootDomain = rootDomain;
    newProposal.inFavor = 0;
    newProposal.against = 0;
    newProposal.resolved = false;

    emit ProposalCreated(proposalCount, proposalType, rootDomain, rootDomain);
}


    function vote(uint256 proposalId, Vote voteChoice)
        external
        validRootDomain(allowList[entryKeys[0]].rootDomain)
    {
        require(proposalId > 0 && proposalId <= proposalCount, "Invalid proposal ID");
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.resolved, "Proposal already resolved");
        require(
            proposal.votes[allowList[entryKeys[0]].rootDomain] == Vote.None,
            "Already voted"
        );

        if (voteChoice == Vote.InFavor) {
            proposal.inFavor++;
        } else {
            proposal.against++;
        }

        proposal.votes[allowList[entryKeys[0]].rootDomain] = voteChoice;
        emit Voted(proposalId, allowList[entryKeys[0]].rootDomain, voteChoice);

        // Check resolution
        if (proposal.inFavor > rootDomainCount / 2) {
            proposal.resolved = true;
            emit ProposalResolved(proposalId, true);
            if (proposal.proposalType == ProposalType.Add) {
                addRootDomain(proposal.rootDomain);
            } else {
                removeRootDomain(proposal.rootDomain);
            }
        } else if (proposal.against >= rootDomainCount / 2) {
            proposal.resolved = true;
            emit ProposalResolved(proposalId, false);
        }
    }

    function addEntry(string memory entry, string memory comment) external {
        require(bytes(entry).length > 0, "Entry cannot be empty");
        require(bytes(comment).length > 0, "Comment cannot be empty");
        
        Chainlink.Request memory req = buildChainlinkRequest(
            jobId,
            address(this),
            this.fulfillDnsVerification.selector
        );
        req.add("get", entry);
        bytes32 requestId = sendChainlinkRequest(req, oraclePayment);
        requestIdToEntry[requestId] = entry;
        dnsVerificationRequests[requestId] = DnsVerificationRequest({
            entry: entry,
            sender: msg.sender
        });
        allowList[entry] = Entry({
            entry: entry,
            rootDomain: entry,
            comment: comment,
            isVerified: false
        });
        entryKeys.push(entry);
        emit EntryAdded(requestId, entry, comment);
    }

    function fulfillDnsVerification(
        bytes32 requestId,
        uint256 statusCode,
        bytes32 data
    ) external recordChainlinkFulfillment(requestId) {
        DnsVerificationRequest memory dnsRequest = dnsVerificationRequests[
            requestId
        ];
        string memory entry = dnsRequest.entry;

        if (statusCode == 200 && data.length > 0) {
            allowList[entry].isVerified = true;
            emit EntryVerificationSucceeded(entry);
        } else {
            delete allowList[entry];
            for (uint256 i = 0; i < entryKeys.length; i++) {
                if (
                    keccak256(abi.encodePacked(entryKeys[i])) ==
                    keccak256(abi.encodePacked(entry))
                ) {
                    entryKeys[i] = entryKeys[entryKeys.length - 1];
                    entryKeys.pop();
                    break;
                }
            }
            emit EntryVerificationFailed(entry, "DNS Verification Failed");
        }
        delete dnsVerificationRequests[requestId];
    }

    function updateEntry(string memory entry, string memory newComment)
        external
        validRootDomain(allowList[entry].rootDomain)
    {
        require(bytes(newComment).length > 0, "Comment cannot be empty");
        allowList[entry].comment = newComment;
        emit EntryUpdated(entry, newComment);
    }
}
