"""Access control list for ShadowGate Proxy."""

import ipaddress
import logging
from typing import Tuple, List, Set

from shadowgate.config import Config

logger = logging.getLogger("shadowgate.proxy.acl")


class AccessController:
    """Access controller for IP and domain filtering."""

    def __init__(self, config: Config):
        self.config = config

        # Load lists from config — keys match config/default.yaml
        raw_whitelist = self.config.get("proxy", "acl", "whitelist", default=[]) or []
        raw_blacklist = self.config.get("proxy", "acl", "blacklist", default=[]) or []
        raw_blocked = self.config.get("proxy", "acl", "blocked_domains", default=[]) or []

        self.whitelist_ips: List[str] = list(raw_whitelist)
        self.blacklist_ips: Set[str] = set(raw_blacklist)
        self.blocked_domains: List[str] = list(raw_blocked)

        self.whitelist_networks = []
        for ip in self.whitelist_ips:
            try:
                self.whitelist_networks.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                logger.error(f"Invalid whitelist IP/CIDR: {ip}")

        self.blacklist_networks = []
        for ip in self.blacklist_ips:
            try:
                self.blacklist_networks.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                logger.error(f"Invalid blacklist IP/CIDR: {ip}")

    def is_allowed(self, client_ip: str, target_host: str = "") -> Tuple[bool, str]:
        """Check if request is allowed based on client IP and target host."""
        # 1. Check IP blacklist
        if self._check_ip_blacklist(client_ip):
            return False, "IP is blacklisted"

        # 2. Check IP whitelist (if whitelist is not empty, only allow whitelisted IPs)
        if self.whitelist_networks and not self._check_ip_whitelist(client_ip):
            return False, "IP is not whitelisted"

        # 3. Check domain blocklist
        if target_host and self._check_domain_blocked(target_host):
            return False, "Target domain is blocked"

        return True, "Allowed"

    def _check_ip_whitelist(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def _check_ip_blacklist(self, ip: str) -> bool:
        if ip in self.blacklist_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.blacklist_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def _check_domain_blocked(self, host: str) -> bool:
        host = host.lower()
        for domain in self.blocked_domains:
            domain = domain.lower()
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def add_to_blacklist(self, ip: str) -> None:
        """Add an IP or CIDR to the blacklist."""
        self.blacklist_ips.add(ip)
        try:
            network = ipaddress.ip_network(ip, strict=False)
            self.blacklist_networks.append(network)
            logger.info(f"Added {ip} to blacklist")
        except ValueError:
            logger.error(f"Invalid IP/CIDR to blacklist: {ip}")

    def remove_from_blacklist(self, ip: str) -> None:
        """Remove an IP or CIDR from the blacklist."""
        if ip in self.blacklist_ips:
            self.blacklist_ips.remove(ip)

        try:
            network_to_remove = ipaddress.ip_network(ip, strict=False)
            self.blacklist_networks = [
                n for n in self.blacklist_networks if n != network_to_remove
            ]
            logger.info(f"Removed {ip} from blacklist")
        except ValueError:
            pass
