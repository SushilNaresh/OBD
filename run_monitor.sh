export OBD_HOST=10.20.10.119
export OBD_USER=dev
export OBD_KEY=~/.ssh/goldilocks.pem
export OBD_PASS='rwIqWmq6LG3EWZge'
#./monitor.sh -w 10
./monitor.sh -h 10.20.10.119 -u dev -P rwIqWmq6LG3EWZge --norot -w 30

