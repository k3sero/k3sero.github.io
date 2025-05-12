---
title: Hidden Orangutan - Damctf2025
author: Kesero
description: Reto Cripto basado en un cifrado por transposición utilizando una partida de ajedrez
date: 2025-05-11 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Cripto, Cripto - Encodings, Writeups, Dificultad - Media]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Cripto/Hidden%20Orangutan/img/4.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `sterben3254`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Alice and Bob have been playing a lot of chess lately... and sending some weird messages..."

## Archivos

En reto nos dan los siguientes archivo.

- `message.txt` : Contiene el mensaje cifrado.
- `2025-05-09\_AlicevsBob.pgn` : Contiene la partida de ajedrez que se ha jugado.

Archivos utilizados [aquí](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Cripto/Hidden%20Orangutan/img/4.png).

## Analizando el código

En `2025-05-09\_AlicevsBob.pgn` encontramos la siguiente información.

```
[Date "2025.05.09"]
[White "Alice"]
[Black "Bob"]
[Result "0-1"]

1. c4 Nf6 2. b4 e5 3. a3 c5 4. b5 a6 5. bxa6 Rxa6 6. e3 g6 7. Bb2 d6 8. Nc3 Nc6
9. d3 Bg7 10. Nf3 O-O 11. Nd2 Re8 12. Be2 d5 13. O-O d4 14. Nb5 dxe3 15. fxe3
Bh6 16. Rf3 Ne7 17. e4 Nc6 18. Nb3 Ng4 19. Bc1 Bxc1 20. Qxc1 Nd4 21. N3xd4 exd4
22. h3 Ne3 23. Rxe3 dxe3 24. Qxe3 Qe7 25. Rf1 Qe5 26. Qf4 Qxf4 27. Rxf4 Ra5 28.
Nd6 Rd8 29. e5 Rxa3 30. Rf1 b6 31. Rb1 Ra6 32. Bf3 Be6 33. Kf2 Rb8 34. Ke3 Kg7
35. Rf1 h5 36. Bd5 Rf8 37. Bb7 Ra2 38. Bc6 Rb2 39. Ne8+ Rxe8 40. Bxe8 Rxg2 41.
h4 Rg3+ 42. Rf3 Rg1 43. Bc6 Re1+ 44. Kd2 Rxe5 45. Rf1 Bg4 46. Bd5 Re2+ 47. Kc3
Bf5 48. Rb1 Re3 49. Rxb6 Rxd3+ 50. Kb2 Rh3 51. Rb5 Rxh4 52. Rxc5 Kf6 53. Rc6+
Be6 54. Bxe6 Rh2+ 55. Kc3 fxe6 56. c5 g5 57. Ra6 Rh1 58. Kd2 Rf1 59. Ra4 Rf4 60.
Ra8 h4 61. Kd3 Ke5 62. Rh8 Rf1 63. Kc4 Rc1+ 64. Kb5 Kf4 65. c6 Kg3 66. Kb6 h3
67. c7 h2 68. Kb7 Kg2 69. c8=Q Rxc8 70. Kxc8 g4 71. Rh5 h1=Q 72. Rc5 Qh8+ 73.
Kb7 g3 74. Rc4 Qh7+ 75. Kb6 Kh2 76. Kc6 g2 77. Rc5 Qe4+ 78. Kc7 g1=Q 79. Rh5+
Kg3 80. Rg5+ Kf2 81. Rxg1 Kxg1 82. Kd7 Qd5+ 83. Kc7 e5 84. Kb6 e4 85. Ka6 e3 86.
Ka7 Qd7+ 87. Kb6 e2 88. Kc5 Qc7+ 89. Kd5 e1=Q 90. Kd4 Qee5+ 91. Kd3 Qcc3# 0-1
```

Aquí podemos observar como `Bob` ha ganado la partida junto a todos los movimientos que se han tomado en ella.

En `message.txt` podemos encontrar el mensaje cifrado que se han intercambiado entre ellos.

```
sudsn __yast  n __fd{3d n___pfhigug1trr}bay t_1 0?udn oh30uhmac4
```

## Solver

Primero de todo, para visualizar la partida de manera gráfica, podemos utilizar páginas web como [chess.com](https://www.chess.com/es/analysis?tab=analysis).

![partida](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Cripto/Hidden%20Orangutan/img/partida.png)

Como podemos observar, en el mensaje cifrado se encuentran las llaves de la flag `{}` es por ello que podemos identificarlo como un mensaje que se ha cifrado utilizando un cifrado de transposición.

Un cifrado de transposición es un método de encriptación que reorganiza el orden de los caracteres del mensaje original sin cambiarlos.

En este caso, podemos observar como justo el mensaje contiene 64 caracteres, el equivalente a uno por cada posición del tablero de ajedrez (8 x 8), por lo que podemos observar que el mensaje cifrado corresponde a la posición final de los caracteres en el tablero de ajedrez. Pongámoslo en perspectiva.

```
    A   B   C   D   E   F   G   H
  +---+---+---+---+---+---+---+---+
8 | s | u | d | s | n | _ | _ | y |
  +---+---+---+---+---+---+---+---+
7 | a | s | t | n | _ | _ | f | d |
  +---+---+---+---+---+---+---+---+
6 | { | 3 | d | n | _ | _ | _ | p |
  +---+---+---+---+---+---+---+---+
5 | f | h | i | g | u | g | 1 | t |
  +---+---+---+---+---+---+---+---+
4 | r | r | } | b | a | y | t | _ |
  +---+---+---+---+---+---+---+---+
3 | 1 | 0 | ? | u | d | n | o | h |
  +---+---+---+---+---+---+---+---+
2 | 3 | 0 | u | h | m | a | c | 4 |
  +---+---+---+---+---+---+---+---+
1 | . |   |   |   |   |   |   |   |
  +---+---+---+---+---+---+---+---+
```

Por lo que para obtener el mensaje en claro, debemos obtener la posición inicial del tablero ya que esta se corresponderían con los caracteres originales y en su sitio. Pero, ¿cómo conseguimos esto?

Básicamente tenemos que revertir el cifrado, es decir, tenemos que mirar las jugadas de atrás para adelante, de esta manera los cambios se van deshaciendo poco a poco hasta obtener dicho estado.

Para ello, tenemos que hacer un script en python que implemente dicha lógica. El script es el siguiente. (Créditos a [Robert Detjens](https://gitlab.com/detjensrobert) por la utilización de un script basado en el módulo `chess` del propio python)

```py
import chess, chess.pgn

class cipherBoard:
    # First value of each column is the bottom,think that white is on bottom
    # (In other words you are on the white side)
    board = {
        "a":[],
        "b":[],
        "c":[],
        "d":[],
        "e":[],
        "f":[],
        "g":[],
        "h":[],
    }

    columns = "abcdefgh"
    
    def populate_board(self, text:str): 
        str_position = 0
        for i in range(8):
            for j in self.columns:
                # If there is still message to add
                if str_position < len(text):
                    # Load backwards to make it map like we or white side
                    self.board[j].insert(0, text[str_position])
                    str_position += 1
                else:
                    self.board[j].insert(0, " ")
            
    def print_board(self): 
        for x in reversed(range(8)):
            row = []
            for j in self.columns:
                row.append(self.board[j][x])
            print(row)
        print("\n\n")

    def print_text(self):
        string = ""
        for x in reversed(range(8)):
            for j in self.columns:
                string += self.board[j][x]
        print(string)

    # f is from, t is to. So swap the board values of the two positions
    def swap_move(self, f:str, t:str):
        f_alpha = f[0]
        f_num = int(f[1])
        t_alpha = t[0]
        t_num = int(t[1])
        f = self.board[f_alpha][f_num-1]
        to = self.board[t_alpha][t_num-1]
        self.board[f_alpha][f_num-1] = to
        self.board[t_alpha][t_num-1] = f

    def encrypt(self, moves:list):
        for x in moves:
            f = x[0:2]
            t = x[2:]
            self.swap_move(f, t)

    def decrypt(self, moves:list):
        self.encrypt(reversed(moves))

board = chess.Board()
moves = [] 
pgn = open("2025-05-09_Alice_vs_Bob.pgn")
game = chess.pgn.read_game(pgn)

for number, move in enumerate(game.mainline_moves()): 
    chess_move = board.push(move)
    moves.append(str(move))

cipherB = cipherBoard()

file = open("../message.txt", 'r')
text = file.read()
cipherB.populate_board(text)

cipherB.print_board()

cipherB.decrypt(moves)
cipherB.print_board()

cipherB.print_text()
```

## Flag

`dam{ch3ss0graphy_1s_fun_but_did_y0u_f1nd_th3_or4ngutan?}`