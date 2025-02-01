sudo apt-get update
sudo apt-get -y upgrade

sudo mkdir -p /etc/fido2_security_key

echo "dtoverlay=dwc2" | sudo tee -a /boot/firmware/config.txt
echo "dwc2" | sudo tee -a /etc/modules
echo "libcomposite" | sudo tee -a /etc/modules

sudo apt-get install -y python3 python3-dev python3-pip
sudo apt-get install -y python3-cbor2 python3-cryptography python3-ecdsa 


sudo cp ctap_init /usr/bin
sudo chmod +x /usr/bin/ctap_init

sudo cp security_key.py /usr/bin
sudo chmod +x /usr/bin/security_key.py

sudo cp security_key_logs /usr/bin
sudo chmod +x /usr/bin/security_key_logs

sudo cp usbgadget.service /lib/systemd/system
sudo chmod 644 /lib/systemd/system/usbgadget.service
sudo systemctl daemon-reload
sudo systemctl enable usbgadget
sudo systemctl restart usbgadget

sudo cp security_key_service.service /lib/systemd/system
sudo chmod 644 /lib/systemd/system/usbgadget.service
sudo systemctl daemon-reload
sudo systemctl enable security_key_service
sudo systemctl restart security_key_service

sudo reboot





