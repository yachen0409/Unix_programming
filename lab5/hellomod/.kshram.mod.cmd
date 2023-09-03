cmd_/home/iammrchen/lab5/hellomod/kshram.mod := printf '%s\n'   kshram.o | awk '!x[$$0]++ { print("/home/iammrchen/lab5/hellomod/"$$0) }' > /home/iammrchen/lab5/hellomod/kshram.mod
