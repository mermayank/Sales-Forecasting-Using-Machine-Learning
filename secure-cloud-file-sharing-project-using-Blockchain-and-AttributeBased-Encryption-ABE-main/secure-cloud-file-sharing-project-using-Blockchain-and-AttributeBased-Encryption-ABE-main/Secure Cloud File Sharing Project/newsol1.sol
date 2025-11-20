// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControl {
    struct User {
        bytes32 userId;
        string username;
        bytes32 passwordHash;
        string name;
        string email;
        string department;
        string subscriptionPeriod;
    }

    struct ReqData {
        bytes request;
        bytes response;
        uint8 status; // 0: Pending, 1: Approved, 2: Rejected
    }

    struct FileMetadataStruct {
        string fileLink;     // Store chunk hashes
        address[] uploaders;
        bytes iv;
        bytes cipherKey;
        string[] accessPolicy;
        bytes coefficients; // Coefficients for access control
        bytes32[] request_id;
        bytes32 fileHash;
        bytes32 fileId;
        string filename;
    }
    bytes32[] public fileIdList;

    mapping(string => address) public usernameToAddress;
    mapping(address => User) public users;
    mapping(bytes32 => ReqData) public AccessList;
    mapping(bytes32 => FileMetadataStruct) public FileMetadata;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied: Only owner allowed");
        _;
    }

    event UserRegistered(address indexed userAddress, string username);
    event AccessRequested(bytes32 indexed requestId, address indexed user);
    event AccessGranted(bytes32 indexed requestId, address indexed user);
    event AccessRevoked(bytes32 indexed requestId);
    event FileMetadataUploaded(bytes32 indexed fileId, FileMetadataStruct metadata);
    event FileMetadataUpdated(bytes32 indexed fileId, FileMetadataStruct metadata);
    event AddedUserKeys(bytes32 indexed fileId, bytes32 userId, string[] names);

    constructor() {
        owner = msg.sender;
    }

    struct RegisterUserData {
        string username;
        string password;
        string name;
        string email;
        string department;
        string subscriptionPeriod;
    }

    function registerUser (RegisterUserData calldata data) external {
        require(usernameToAddress[data.username] == address(0), "Error: Username already exists");

        bytes32 userId = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        bytes32 passwordHash = keccak256(abi.encodePacked(data.password));

        users[msg.sender] = User(userId, data.username, passwordHash, data.name, data.email, data.department, data.subscriptionPeriod);
        usernameToAddress[data.username] = msg.sender;

        emit UserRegistered(msg.sender, data.username);
    }

    function getUser (string calldata username) external view returns (User  memory) {
        address userAddress = usernameToAddress[username];
        if (userAddress == address(0)) {
            return User("", "", "", "", "", "", "");
        }
        return users[userAddress];
    }

    function requestAccess(bytes32 fileId, bytes32 requestId, bytes calldata encryptedRequest) external {
        require(AccessList[requestId].request.length == 0, "Error: Request already exists");
        AccessList[requestId] = ReqData(encryptedRequest, "", 0);

        FileMetadata[fileId].request_id.push(requestId);
        emit AccessRequested(requestId, msg.sender);
    }

    function grantAccess(
        bytes32 requestId,
        bytes calldata encryptedResponse, uint8 st
    ) external {
        require(AccessList[requestId].request.length != 0, "Error: Request does not exist");
        require(AccessList[requestId].status != 2, "Error: Request already rejected");
        if (st == 1){
            AccessList[requestId].status = 1; 
            AccessList[requestId].response = encryptedResponse;
        }
        else{
            AccessList[requestId].status = 2;
        }
             // Status: 1 (Approved), 2 (Rejected)
        emit AccessGranted(requestId, msg.sender);
    }

    function revokeAccess(bytes32 requestId, bytes32 fileId, FileMetadataStruct calldata updatedMetadata) external {
        require(AccessList[requestId].request.length != 0, "Error: Request does not exist");

        AccessList[requestId].response = "";
        FileMetadata[fileId] = updatedMetadata;

        emit AccessRevoked(requestId);
    }
    function getResponse(bytes32 requestId) external view returns (bytes memory) {
        require(AccessList[requestId].request.length != 0, "Error: Request does not exist");
        if (AccessList[requestId].status == 2){
            return hex"02"; }
        if (AccessList[requestId].status == 0){
            return hex"00"; }
        if (AccessList[requestId].status == 1) {
            return AccessList[requestId].response;
        }
        return "";
    }
    function getRequest(bytes32 requestId) external view returns (bytes memory) {
        if (AccessList[requestId].status == 0){
            return AccessList[requestId].request; }
        else{
            return hex"00";
        }
    }
    
    function getFileMetadata(bytes32 fileId, bytes32 fileHash) external view returns (FileMetadataStruct memory) {
        if(FileMetadata[fileId].fileHash == bytes32(0)){ 
            for (uint256 i = 0; i < fileIdList.length; i++) {
                bytes32 file_id = fileIdList[i];
                if (FileMetadata[file_id].fileHash == fileHash) {
                    return FileMetadata[file_id];
                }
            }
            return FileMetadata[fileId];
        }
        return FileMetadata[fileId];
    }
    function getFileMetadata(bytes32 fileId) external view returns (FileMetadataStruct memory) {
        return FileMetadata[fileId];
    }
    function uploadFileMetadata(bytes32 fileId, FileMetadataStruct calldata metadata) external {
        FileMetadata[fileId] = metadata;
        fileIdList.push(fileId);
        emit FileMetadataUploaded(fileId, metadata);
    }
    function updateFileMetadata(bytes32 fileId, FileMetadataStruct calldata metadata) external {
        FileMetadata[fileId] = metadata;
        emit FileMetadataUpdated(fileId, metadata);
    }

    function getUserAddress(string memory username) public view returns (address) {
        return usernameToAddress[username];
    }
}