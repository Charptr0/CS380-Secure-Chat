# CSC 380 Secure Chat

## Installation

### Perquisites
0. git `sudo apt install git`
1. g++ `sudo apt install g++`
2. make `sudo apt install make`

### Getting this repo
0. Create a new folder on your VM `mkdir your-folder-name`
1. Go into that new folder `cd your-folder-name`
1. Run `git init`
2. Run `git remote add origin https://github.com/Charptr0/CS380-Secure-Chat.git`
3. Run `git pull origin master` 

### Actual Packages (Debian based distros)
1. ncurses `sudo apt-get install libncurses-dev`
2. readline `sudo apt-get install libreadline8 libreadline-dev`
3. openssl `sudo apt-get install libssl-dev`
4. gmp `sudo apt-get install libgmp3-dev`

### Create a branch
NEVER PUSH TO THE MASTER BRANCH DIRECTLY
1. Create a new branch `git branch your-branch`
2. Checkout into that branch `git checkout your-branch`

### Pushing to this repo
1. Add your changes `git add .`
2. Commit your changes `git commit -m "commit-message"`
3. Push `git push origin your-branch-name`