#!/bin/bash
sudo docker stop $(sudo docker ps -aq)
sudo docker rm $(sudo docker ps -aq)
sudo docker rmi $(sudo docker images -q)
sudo docker volume prune --all --force
sudo docker volume rm $(sudo docker volume ls | awk '{ print $2 }')
sudo docker network prune -f
