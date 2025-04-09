#!/bin/bash
sudo dnf update -y
sudo dnf install -y qemu-kvm libvirt-daemon-system libvirt-clients virt-manager bridge-utils python3 python3-pip python3-libvirt ansible libxml2-utils xsltproc git sshpass
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER
sudo pip3 install ansible-runner xmltodict
mkdir -p ~/projects/darkmesh/{templates,images}
sudo virsh net-define /etc/libvirt/qemu/networks/default.xml || true
sudo virsh net-start default
sudo virsh net-autostart default
ansible-galaxy collection install community.general
git clone https://github.com/Al3x-Myku/DarkMesh.git ~/projects/darkmesh/app
if ! grep -q "options kvm-intel nested=1" /etc/modprobe.d/kvm.conf; then
    echo "options kvm-intel nested=1" | sudo tee -a /etc/modprobe.d/kvm.conf
    sudo modprobe -r kvm_intel
    sudo modprobe kvm_intel
fi
sudo useradd -m ansible
echo "ansible:ansible" | sudo chpasswd
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ansible
sudo chmod 0440 /etc/sudoers.d/ansible
sudo mkdir -p /home/ansible/.ssh
sudo ssh-keygen -t rsa -b 4096 -f /home/ansible/.ssh/id_rsa -N ""
sudo cat /home/ansible/.ssh/id_rsa.pub | sudo tee /home/ansible/.ssh/authorized_keys
sudo chown -R ansible:ansible /home/ansible/.ssh
sudo chmod 700 /home/ansible/.ssh
sudo chmod 600 /home/ansible/.ssh/authorized_keys
if [ -d ~/projects/darkmesh/app ]; then
    cd ~/projects/darkmesh/app
    if [ -f requirements.txt ]; then
        sudo pip3 install -r requirements.txt
    fi
fi
sudo systemctl restart libvirtd
echo ""
echo "Setup complete!"
echo "1. Log out and back in for group changes to take effect"
echo "2. Place your VM images in ~/projects/darkmesh/images/"
echo "3. Test with: virsh list --all"
echo "4. You might need to reboot for all changes to take effect"
echo "5. The ansible user has been created with password 'ansible'"
echo "6. SSH keys have been generated for the ansible user"
echo "7. To run DarkMesh: cd ~/projects/darkmesh/app && python3 main.py (if available)"