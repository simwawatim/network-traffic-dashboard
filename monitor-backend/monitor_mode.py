import subprocess
import signal
import sys

def run_cmd(cmd):
    """Run a shell command, return (success, output)."""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return True, output.strip()
    except subprocess.CalledProcessError as e:
        return False, e.output.strip()

def set_monitor_mode(interface):
    print(f"[+] Setting {interface} to monitor mode...")
    run_cmd(f"sudo ip link set {interface} down")
    run_cmd(f"sudo iw dev {interface} set monitor control")
    run_cmd(f"sudo ip link set {interface} up")

def set_managed_mode(interface):
    print(f"[+] Restoring {interface} to managed mode...")
    run_cmd(f"sudo ip link set {interface} down")
    run_cmd(f"sudo iw dev {interface} set type managed")
    run_cmd(f"sudo ip link set {interface} up")

def enable_monitor_mode_with_cleanup(interface):
    """
    Enable monitor mode on interface and register cleanup on program exit
    """
    set_monitor_mode(interface)

    def cleanup(signum, frame):
        print("\n[!] Signal received, restoring interface...")
        set_managed_mode(interface)
        print("[✓] Interface restored. Exiting.")
        sys.exit(0)

    # Register cleanup handlers for termination signals
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
