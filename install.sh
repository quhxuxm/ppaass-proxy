#Prepare base env
sudo apt update
sudo apt upgrade -y
sudo apt install gcc -y
sudo apt install libfontconfig -y
sudo apt install libfontconfig1-dev -y
sudo apt install dos2unix -y
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo apt install unzip -y
sudo apt install git -y
sudo apt install bind9 -y
echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
sysctl -p
sudo curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update
#Create swap file
sudo swapoff /swapfile
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
sudo free -h
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Start install ppaass
sudo ps -ef | grep ppaass-proxy | grep -v grep | awk '{print $2}' | xargs sudo kill

sudo rm -rf /ppaass-proxy/build
sudo rm -rf /ppaass-proxy/sourcecode
# Build
sudo mkdir /ppaass-proxy
sudo mkdir /ppaass-proxy/sourcecode
sudo mkdir /ppaass-proxy/build
sudo mkdir /ppaass-proxy/build/resources

# Pull ppaass
cd /ppaass-proxy/sourcecode
sudo git clone -b main https://github.com/quhxuxm/ppaass-proxy.git ppaass-proxy
sudo chmod 777 ppaass-proxy
cd /ppaass-proxy/sourcecode/ppaass-proxy
sudo git pull

cargo build --release

# ps -ef | grep gradle | grep -v grep | awk '{print $2}' | xargs kill -9
sudo cp -r /ppaass-proxy/sourcecode/ppaass-proxy/resources/ /ppaass-proxy/build/
sudo cp /ppaass-proxy/sourcecode/ppaass-proxy/target/release/ppaass-proxy /ppaass-proxy/build
sudo cp /ppaass-proxy/sourcecode/ppaass-proxy/ppaass-proxy-start.sh /ppaass-proxy/build/

sudo chmod 777 /ppaass-proxy/build
cd /ppaass-proxy/build
ls -l

sudo chmod 777 ppaass-proxy
sudo chmod 777 *.sh
sudo dos2unix ./ppaass-proxy-start.sh

#Start with the low configuration by default
sudo nohup ./ppaass-proxy-start.sh >run.log 2>&1 &

ulimit -n 409600

