"""Environment-managed source profiles. Peer IPs come from the socket, never payload headers."""

import ipaddress
import os
from dataclasses import dataclass

PROFILES = {
    "fortinet": ("FORTINET_IPS", "Fortinet", "FortiGate", "security"),
    "paloalto": ("PALOALTO_IPS", "Palo Alto Networks", "PAN-OS", "security"),
    "cisco": ("CISCO_IPS", "Cisco", "Network device", "network"),
    "windows": ("WINDOWS_IPS", "Microsoft", "Windows / AD", "server"),
    "linux": ("LINUX_IPS", "Linux", "Linux", "server"),
    "aws": ("AWS_IPS", "AWS", "AWS logs", "cloud"),
    "kubernetes": ("KUBERNETES_IPS", "Kubernetes", "Container logs", "application"),
}


def peer_address(peer):
    address = ipaddress.ip_address(peer)
    return (
        address.ipv4_mapped
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
        else address
    )


def boolean(value, name):
    if value.lower() not in ("true", "false"):
        raise ValueError(f"{name} must be true or false")
    return value.lower() == "true"


@dataclass
class SourceSettings:
    networks: dict
    syslog_enabled: bool = True
    syslog_bind: str = "0.0.0.0"
    syslog_port: int = 5514
    spool: str = "data/source-push.db"
    require_token: bool = False

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        networks = {}
        for source, (variable, _, _, _) in PROFILES.items():
            values = env.get(variable, "").strip()
            networks[source] = []
            if values:
                for item in values.split(","):
                    try:
                        networks[source].append(ipaddress.ip_network(item.strip(), strict=False))
                    except ValueError:
                        raise ValueError(f"{variable} contains an invalid IP/CIDR") from None
        settings = cls(
            networks=networks,
            syslog_enabled=boolean(env.get("SYSLOG_ENABLED", "true"), "SYSLOG_ENABLED"),
            syslog_bind=env.get("SYSLOG_BIND_IP", env.get("LISTEN_IP", "0.0.0.0")),
            syslog_port=int(env.get("SYSLOG_PORT", "5514")),
            spool=env.get("SOURCE_PUSH_SPOOL", "data/source-push.db"),
            require_token=boolean(
                env.get("SOURCE_PUSH_REQUIRE_TOKEN", "false"), "SOURCE_PUSH_REQUIRE_TOKEN"
            ),
        )
        if not 1 <= settings.syslog_port <= 65535:
            raise ValueError("SYSLOG_PORT must be 1-65535")
        ipaddress.ip_address(settings.syslog_bind)
        if settings.syslog_enabled:
            enabled = [(name, net) for name, nets in networks.items() for net in nets]
            for index, (name, network) in enumerate(enabled):
                for other_name, other in enabled[index + 1 :]:
                    if (
                        name != other_name
                        and network.version == other.version
                        and network.overlaps(other)
                    ):
                        raise ValueError(
                            f"Ambiguous Syslog IP ranges: {name} and {other_name}; use distinct IPs or SYSLOG_ENABLED=false for HTTP-only routing"
                        )
        return settings

    def permits(self, source, peer):
        try:
            address = peer_address(peer)
        except ValueError:
            return False
        return any(address in net for net in self.networks.get(source, []))

    def source_for(self, peer):
        matches = [source for source in PROFILES if self.permits(source, peer)]
        return matches[0] if len(matches) == 1 else None

    def describe(self):
        return [
            {
                "source": name,
                "enabled": bool(self.networks[name]),
                "allowed_ips": [str(net) for net in self.networks[name]],
                "endpoint": f"/api/v1/logs/{name}",
                "vendor": metadata[1],
                "product": metadata[2],
                "normalizer": f"{name}-v1",
            }
            for name, metadata in PROFILES.items()
        ]
