---
layout: page
type: about
title: About
---

<br>
Hello! I'm Akif, a passionate Computer Networks student with a love for Cybersecurity. I started my journey in Cybersecurity by playing CTF in December 2022. I am eager to learn more about different areas of Cybersecurity. This blog is all about my journey, writeups and notes for future references.

If you'd like to connect or learn more about what I do, feel free to reach out to me via email at <a href="mailto:muhd.akif1107@gmail.com">muhd.akif1107@gmail.com</a>, or through any of my social medias.

---
Thank you for visiting my website! I hope you find something here that inspires you.


## Play a Game: Tic-Tac-Toe

<div id="tic-tac-toe">
  <table>
    <tr>
      <td class="cell" onclick="makeMove(this, 0)"></td>
      <td class="cell" onclick="makeMove(this, 1)"></td>
      <td class="cell" onclick="makeMove(this, 2)"></td>
    </tr>
    <tr>
      <td class="cell" onclick="makeMove(this, 3)"></td>
      <td class="cell" onclick="makeMove(this, 4)"></td>
      <td class="cell" onclick="makeMove(this, 5)"></td>
    </tr>
    <tr>
      <td class="cell" onclick="makeMove(this, 6)"></td>
      <td class="cell" onclick="makeMove(this, 7)"></td>
      <td class="cell" onclick="makeMove(this, 8)"></td>
    </tr>
  </table>
  <p id="status"></p>
  <button onclick="resetGame()">Reset Game</button>
</div>

<style>
#tic-tac-toe {
    display: flex;
    flex-direction: column;
    align-items: center;
}

table {
    border-collapse: collapse;
}

td.cell {
    width: 60px;
    height: 60px;
    text-align: center;
    font-size: 24px;
    border: 1px solid #333;
    cursor: pointer;
}

button {
    margin-top: 10px;
    padding: 5px 10px;
    font-size: 16px;
}

#status {
    margin-top: 10px;
    font-size: 18px;
    font-weight: bold;
}
</style>

<script>
let board = ["", "", "", "", "", "", "", "", ""];
let currentPlayer = "X";
let gameActive = true;

const winningConditions = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6]
];

function makeMove(cell, index) {
    if (board[index] === "" && gameActive) {
        board[index] = currentPlayer;
        cell.innerHTML = currentPlayer;
        checkWinner();
        currentPlayer = currentPlayer === "X" ? "O" : "X";
    }
}

function checkWinner() {
    let roundWon = false;
    for (let i = 0; i < winningConditions.length; i++) {
        const [a, b, c] = winningConditions[i];
        if (board[a] !== "" && board[a] === board[b] && board[a] === board[c]) {
            roundWon = true;
            break;
        }
    }

    if (roundWon) {
        document.getElementById("status").innerHTML = `Player ${currentPlayer} wins!`;
        gameActive = false;
        return;
    }

    if (!board.includes("")) {
        document.getElementById("status").innerHTML = "It's a draw!";
        gameActive = false;
    }
}

function resetGame() {
    board = ["", "", "", "", "", "", "", "", ""];
    currentPlayer = "X";
    gameActive = true;
    document.querySelectorAll("td.cell").forEach(cell => cell.innerHTML = "");
    document.getElementById("status").innerHTML = "";
}
</script>
