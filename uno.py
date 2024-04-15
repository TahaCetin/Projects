import random

class UnoCard:
    def __init__(self, color, number):
        self.color = color
        self.number = number 

    def __str__(self):
        return self.color + ' ' + str(self.number)

    def canPlay(self, c):
        if self.color == c.color:
            return True
        elif self.number == c.number:
            return True
        return False

class CollectionOfUnoCards:
    def __init__(self):
        self.cardList = []

    def __str__(self):
        collection = ''
        for i in range(0, self.getNumCards()):
            collection = collection +  str(i) + ': ' + self.cardList[i].__str__() + ', '
        return collection

    def getNumCards(self):
        return len(self.cardList)

    def addCard(self, c):
        self.cardList.append(c)

    def shuffle(self):
        for i in range(0,200):
            firstCardIndex = random.randrange(0, self.getNumCards())
            secondCardIndex = random.randrange(0, self.getNumCards())
            firstCard = self.cardList[firstCardIndex]
            secondCard = self.cardList[secondCardIndex]
            self.cardList[firstCardIndex] = secondCard
            self.cardList[secondCardIndex] = firstCard

    def getTopCard(self):
        card = self.cardList.pop(-1)
        return card

    def canPlay(self, c):
        for i in range(0, self.getNumCards()):
            if self.cardList[i].canPlay(c):
                return True
        return False

    def getCard(self, index):
        card = self.cardList.pop(index)
        return card

class Uno:
    def __init__(self):
        self.deck = CollectionOfUnoCards()
        for j in range(1, 3):
            for i in range(1,10):
                self.deck.addCard(UnoCard('Green', i))
                self.deck.addCard(UnoCard('Blue', i))
                self.deck.addCard(UnoCard('Yellow', i))
                self.deck.addCard(UnoCard('Red', i))
        self.deck.shuffle()
        self.hand1 = CollectionOfUnoCards()
        self.hand2 = CollectionOfUnoCards()
        for i in range(1,15):
            if i%2 == 1:
                self.hand1.addCard(self.deck.cardList[i])
            else:
                self.hand2.addCard(self.deck.cardList[i])
        self.lastPlayedCard = UnoCard(0,'Green')

    def playGame(self):
        print('Player 1 Plays')
        print('Your cards:')
        print(self.hand1.__str__())
        print('Enter index of the card you want to play:')
        selected = input()
        selected = int(selected)
        self.lastPlayedCard = self.hand1.getCard(selected)
        i = 1
        while self.hand1.getNumCards() > 0 and self.hand2.getNumCards() > 0 and self.deck.getNumCards() > 0:
            self.playTurn(i%2 + 1)
            i = i+1
            print()
        self.printResult()
    def playTurn(self, player):
        if player == 1:
            if self.hand1.canPlay(self.lastPlayedCard):
                print('Last played card is:')
                print(self.lastPlayedCard)
                print('Player 1 Plays')
                print('Your cards:')
                print(self.hand1.__str__())
                print('Enter index of the card you want to play:')
                selected = input()
                selected = int(selected)
                while self.hand1.cardList[selected].canPlay(self.lastPlayedCard) == False:
                    print('Can not play that. Pick again:')
                    selected = int(input())
                self.lastPlayedCard = self.hand1.getCard(selected)
            else:
                print('Player 1 draws from deck.')
                self.hand1.addCard(self.deck.getTopCard())
        elif player == 2:
            if self.hand2.canPlay(self.lastPlayedCard):
                print('Last played card is:')
                print(self.lastPlayedCard)
                print('Player 2 Plays')
                print('Your cards:')
                print(self.hand2.__str__())
                print('Enter index of the card you want to play:')
                selected = int(input())
                while self.hand2.cardList[selected].canPlay(self.lastPlayedCard) == False:
                    print('Can not play that. Pick again:')
                    selected = int(input())
                self.lastPlayedCard = self.hand2.getCard(selected)
            else:
                print('Player 2 draws from deck.')
                self.hand2.addCard(self.deck.getTopCard())


    def printResult(self):
        if self.hand1.getNumCards() == 0:
            print('Player 1 Won!')
        elif self.hand2.getNumCards() == 0:
            print('Player 2 Won!')
        else:
            print('Tie.')


my_game = Uno()
my_game.playGame()



