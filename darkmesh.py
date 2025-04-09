#!/usr/bin/env python3
import sys
import os
import time
import json
import libvirt
import shutil
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
import ansible_runner

path_templates = "/home/tony/projects/darkmesh/templates/vulnerabilities"

class VMOrchestrator:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.conn = None
        self.vms = []
        self.network_name = "default"
        self.playbooks_dir = os.path.join(os.path.dirname(os.path.abspath(xml_file)), path_templates)
        
    def connect_to_hypervisor(self):
        try:
            self.conn = libvirt.open("qemu:///system")
            if self.conn is None:
                raise Exception("Failed to connect to the hypervisor")
            print("Successfully connected to the hypervisor")
        except libvirt.libvirtError as e:
            print(f"Error connecting to hypervisor: {e}", file=sys.stderr)
            sys.exit(1)
    
    def parse_xml_config(self):
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()

            network_elem = root.find("network")
            if network_elem is not None and network_elem.get("name"):
                self.network_name = network_elem.get("name")
            
            vm_elems = root.findall("vm")
            if len(vm_elems) < 1:
                raise Exception("At least one VM configuration is required")
            
            for vm_elem in vm_elems:
                vm_name = vm_elem.get("name")
                if not vm_name:
                    raise Exception("VM name not specified in XML file")
                
                vm_image = vm_elem.get("image")
                if not vm_image:
                    raise Exception("VM image not specified in XML file")
                
                shutil.copy(f"templates/images/{vm_image}.qcow2", f"{vm_name}.qcow2")
                
                vm_config = {
                    "name": vm_name,
                    "memory": int(vm_elem.find("memory").text) if vm_elem.find("memory") is not None else 1024,
                    "vcpus": int(vm_elem.find("vcpus").text) if vm_elem.find("vcpus") is not None else 1,
                    "disk": f"/home/tony/projects/darkmesh/{vm_name}.qcow2",
                    "ansible": []
                }

                playbook_elems = vm_elem.findall("playbook")
                for playbook_elem in playbook_elems:
                    playbook_config = {
                        "vuln": playbook_elem.get("vuln"),
                    }
                    
                    vm_config["ansible"].append(playbook_config)
                
                self.vms.append(vm_config)
            
            print(f"Successfully parsed XML configuration")
            print(f"Using network: {self.network_name}")
            for idx, vm in enumerate(self.vms):
                print(f"VM {idx+1}: {vm['name']} (Memory: {vm['memory']}MB, vCPUs: {vm['vcpus']}, Disk: {vm['disk']})")
                if vm["ansible"]:
                    print(f"  Ansible Playbooks: {len(vm['ansible'])}")
                    for i, playbook in enumerate(vm["ansible"]):
                        print(f"    {i+1}. {playbook['vuln'] or 'Custom playbook'}")
            
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error in configuration: {e}", file=sys.stderr)
            sys.exit(1)
    
    def ensure_default_network(self):
        try:
            try:
                network = self.conn.networkLookupByName(self.network_name)

                if not network.isActive():
                    network.create()
                    print(f"Network '{self.network_name}' was inactive, started it")
                else:
                    print(f"Network '{self.network_name}' is already active, using it")
                
                return
            except libvirt.libvirtError:
                if self.network_name != "default":
                    print(f"Warning: Network '{self.network_name}' not found, will try to create a default network")
                    self.network_name = "default"
                
                try:
                    network = self.conn.networkLookupByName("default")
                    if not network.isActive():
                        network.create()
                    print(f"Using existing default network")
                    return
                except libvirt.libvirtError:
                    pass
            
            default_net_xml = """
            <network>
              <name>default</name>
              <forward mode="nat"/>
              <bridge name="virbr0" stp="on" delay="0"/>
              <ip address="192.168.122.1" netmask="255.255.255.0">
                <dhcp>
                  <range start="192.168.122.2" end="192.168.122.254"/>
                </dhcp>
              </ip>
            </network>
            """
            
            network = self.conn.networkDefineXML(default_net_xml)
            network.setAutostart(True)
            network.create()
            print("Created and started default network")
            
        except libvirt.libvirtError as e:
            print(f"Error managing network: {e}", file=sys.stderr)
            sys.exit(1)
    
    def create_vm(self, vm_config):
        try:
            try:
                domain = self.conn.lookupByName(vm_config["name"])
                print(f"VM '{vm_config['name']}' already exists")

                if domain.isActive() == 0:
                    domain.create()
                    print(f"Started VM '{vm_config['name']}'")
                else:
                    print(f"VM '{vm_config['name']}' is already running")
                
                return domain
            except libvirt.libvirtError:
                pass
            
            mac_address = "52:54:00:00:00:" + ":".join([f"{n:02x}" for n in [ord(c) for c in vm_config["name"][-1:]]])
            
            vm_xml = f"""
            <domain type="kvm">
                <name>{vm_config["name"]}</name>
                <memory unit="MiB">{vm_config["memory"]}</memory>
                <vcpu>{vm_config["vcpus"]}</vcpu>
                <os>
                    <type arch="x86_64">hvm</type>
                    <boot dev="hd"/>
                </os>
                <features>
                    <acpi/>
                    <apic/>
                </features>
                <devices>
                    <emulator>/usr/bin/qemu-system-x86_64</emulator>
                    <disk type="file" device="disk">
                        <driver name="qemu" type="qcow2"/>
                        <source file="{vm_config["disk"]}"/>
                        <target dev="vda" bus="virtio"/>
                    </disk>
                    <interface type="network">
                        <source network="{self.network_name}"/>
                        <mac address="{mac_address}"/>
                        <model type="virtio"/>
                    </interface>
                    <console type="pty">
                        <target type="serial" port="0"/>
                    </console>
                    <graphics type="vnc" port="-1" autoport="yes" listen="0.0.0.0">
                        <listen type="address" address="0.0.0.0"/>
                    </graphics>
                </devices>
            </domain>
            """
            
            domain = self.conn.defineXML(vm_xml)
            if domain is None:
                raise Exception(f"Failed to define VM '{vm_config['name']}'")
            
            domain.create()
            print(f"Successfully created and started VM '{vm_config['name']}'")
            return domain
            
        except libvirt.libvirtError as e:
            print(f"Error creating VM: {e}", file=sys.stderr)
            sys.exit(1)
    
    def get_vm_dhcp_info(self):
        try:
            network = self.conn.networkLookupByName(self.network_name)
            dhcp_leases = network.DHCPLeases()
            
            vm_info = {}
            for vm in self.vms:
                vm_info[vm["name"]] = {"ip": None, "mac": None}
            
            for lease in dhcp_leases:
                for vm in self.vms:
                    domain = self.conn.lookupByName(vm["name"])
                    xml_desc = domain.XMLDesc()
                    if lease['mac'] in xml_desc:
                        vm_info[vm["name"]]["ip"] = lease['ipaddr']
                        vm_info[vm["name"]]["mac"] = lease['mac']
            
            return vm_info
        except libvirt.libvirtError as e:
            print(f"Warning: Could not get DHCP info: {e}")
            return {}
    
    def run_ansible_playbook(self, vm_name, playbook_config, vm_ip):
        try:
            print(f"Running Ansible playbook for {vm_name}...")

            vuln=playbook_config.get("vuln")

            settings = {
                "quiet": False,
                "pexpect_timeout": 120
            }
            
            result = ansible_runner.run(
                playbook=f"/home/tony/projects/darkmesh/templates/vulnerabilities/{vuln}.yml",
                settings=settings,
                cmdline=f"-i {vm_ip},"
            )
            
            if result.status == "successful":
                print(f"Ansible playbook for {vm_name} completed successfully")
                return True
            else:
                print(f"Ansible playbook for {vm_name} failed with status: {result.status}")
                return False
            
        except Exception as e:
            print(f"Error running Ansible playbook for {vm_name}: {e}")
            return False
    
    def orchestrate(self):
        self.connect_to_hypervisor()
        self.parse_xml_config()
        self.ensure_default_network()
        
        domains = []
        for vm_config in self.vms:
            domain = self.create_vm(vm_config)
            domains.append(domain)

        print("\nWaiting for DHCP leases...")
        time.sleep(10)
        
        vm_network_info = self.get_vm_dhcp_info()
        
        for vm_config in self.vms:
            vm_name = vm_config["name"]

            if not vm_config["ansible"]:
                continue
            
            if vm_name not in vm_network_info or not vm_network_info[vm_name]["ip"]:
                print(f"Skipping Ansible playbooks for {vm_name}: No IP address available")
                continue
            
            vm_ip = vm_network_info[vm_name]["ip"]
            print(f"\nConfiguring {vm_name} ({vm_ip}) with Ansible...")
            
            for playbook_config in vm_config["ansible"]:
                success = self.run_ansible_playbook(vm_name, playbook_config, vm_ip)
                if not success:
                    print(f"Warning: Ansible playbook failed for {vm_name}")
        
        print("\nOrchestration complete!")
        print(f"Network: {self.network_name} (NAT)")
        for idx, domain in enumerate(domains):
            state, reason = domain.state()
            state_str = "running" if state == 1 else "not running"
            vm_name = domain.name()
            
            ip_info = ""
            if vm_name in vm_network_info and vm_network_info[vm_name]["ip"]:
                ip_info = f" - IP: {vm_network_info[vm_name]['ip']}"
            
            print(f"VM {idx+1}: {vm_name} - {state_str}{ip_info}")
    
    def cleanup(self):
        if self.conn:
            self.conn.close()
            print("Connection to hypervisor closed")

def main():
    parser = ArgumentParser(description="Orchestrate VMs using libvirt with NAT network and Ansible")
    parser.add_argument("xml_file", help="Path to the XML configuration file")
    args = parser.parse_args()
    
    orchestrator = VMOrchestrator(args.xml_file)
    try:
        orchestrator.orchestrate()
    finally:
        orchestrator.cleanup()

if __name__ == "__main__":
    main()