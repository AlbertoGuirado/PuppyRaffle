### [M-1] Looping thought players array to check duplicates in `PuppyRuffles::enterRuffle` is a potential denial of service (DoS) attack incrementing the gas costs for the future entrants

IMPACT: MEDIUM
LIKELIHOOD: MEDIUM

**Description:** The `PuppyRuffles::enterRuffle` loops though the `players` array to check for duplicates. However, the longer the `PuppyRuffles::players` array is, the more checks a new playuer will have to make. 
This means the gast cost for players who enter right when the raffle starts will be dramatically lower than those who enter later.
Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** The gas costs for raffle entranrs will greatly increase as more players enter the raffle Discoruraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRuffles::entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**
If we have 2 sets of 100 players enter, the cost of gas will be as such:
Gas cost of the first 100 players: 6252048
Gas cost of the second 100 players: 18068138

This is more than x3 more expemsive for the second 100 players.
<details>

```javascript
// @audit DoS attack
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```
Our test
<summary>PoC</summary>

```javascript
    function test_dos() public {
        vm.txGasPrice(1);
        uint256 num = 100;
        //First 100 players
        address[] memory a = new address[](100);
        for (uint256 i = 0; i < a.length; i++) {
            a[i] = address(i);
        }
        uint256 gasSt = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * a.length}(a);
        uint256 gasEnd = gasleft();
        uint256 gasUsed = (gasSt- gasEnd) * tx.gasprice;
        console.log("Gas cost of the first 100 players:", gasUsed);
        //SECOND TIME
        address[] memory a2 = new address[](100);
        for (uint256 i = 0; i < a2.length; i++) {
            a2[i] = address(i+num);
        }
        uint256 gasSt2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * a.length}(a2);
        uint256 gasEnd2 = gasleft();
        uint256 gasUsed2 = (gasSt2- gasEnd2) * tx.gasprice;
        console.log("Gas cost of the second 100 players:", gasUsed2);
        assert(gasUsed < gasUsed2);
    }
```
</details>

**Recommended Mitigation:** There a few recomendations:

1. Consider allowing duplicates -> Users can make new wallet addresses anyways,so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallets address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup
   ```diff
   + mapping(address => uint256) public addressToRaffleId 
   + uint256 public raffleId = 0;
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
            
   +        addressToRaffleId(newPlayers[i]) = raffleId;
        }
   - //Check for duplicates
   + //Check for duplicates only from the new players 
   +        for (uint256 i = 0; i < newPlayers.length; i++) {
   +        require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
   +        }
   -        for (uint256 i = 0; i < newPlayers.length; i++) {
   -            for (uint256 j = 0; j < newPlayers.length; h++) {
   -                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
   -            }
   -        }
            emit RaffleEnter(newPlayers);
        }

        function selectWinner() external{
   +        raffleId = raffleId+1;
            require(block.timestamp >= raffleStartTime+raffleDuration,"PuppyRuffle: Ruffle not over");
        }
   ```
    
### [S-#] Reentrancy attack vector 

**Description:** In the refund 

**Impact:** 

**Proof of Concept:**
  function refund(uint256 playerIndex) public {
        // @audit MEV

        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        payable(msg.sender).sendValue(entranceFee);
        // @audit Reentrancy attack vector -> uploading a variable after send.
        players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }

**Recommended Mitigation:** 