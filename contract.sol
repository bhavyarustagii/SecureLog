pragma solidity ^0.8.0;

contract LogStorage {

    struct LogRecord {
        uint id;
        string hash;
        uint timestamp;
    }

    LogRecord[] public logs;

    function storeLog(string memory hash) public {
        logs.push(LogRecord(logs.length, hash, block.timestamp));
    }

    function getLog(uint index) public view returns(string memory){
        return logs[index].hash;
    }

    function getTotalLogs() public view returns(uint){
        return logs.length;
    }
}