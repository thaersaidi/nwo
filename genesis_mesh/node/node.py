"""Mesh node implementation."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import requests
import nacl.signing

from ..models import GenesisBlock, JoinCertificate, PolicyManifest
from ..crypto import (
    generate_keypair,
    KeyPair,
    load_private_key,
    load_public_key,
    verify_model_signature,
    public_key_from_b64
)

logger = logging.getLogger(__name__)


class MeshNode:
    """
    Genesis Mesh network node.

    A node can act as:
    - Anchor: Gateway/relay node
    - Bridge: Edge resiliency node
    - Client: Endpoint node
    """

    def __init__(
        self,
        genesis_block: GenesisBlock,
        node_keypair: Optional[KeyPair] = None,
        roles: Optional[List[str]] = None
    ):
        """
        Initialize a mesh node.

        Args:
            genesis_block: The network's genesis block
            node_keypair: Node's cryptographic keypair (generates new if None)
            roles: Node roles (default: ['role:client'])
        """
        self.genesis_block = genesis_block
        self.node_keypair = node_keypair or generate_keypair()
        self.roles = roles or ['role:client']
        self.join_certificate: Optional[JoinCertificate] = None
        self.policy_manifest: Optional[PolicyManifest] = None

        # Verify genesis block signatures
        if not self._verify_genesis_block():
            raise ValueError("Genesis block signature verification failed")

        logger.info(f"Node initialized for network: {genesis_block.network_name}")
        logger.info(f"Node public key: {self.node_keypair.public_key_b64}")
        logger.info(f"Roles: {self.roles}")

    def _verify_genesis_block(self) -> bool:
        """
        Verify the genesis block signatures.

        Returns:
            True if all signatures are valid
        """
        if not self.genesis_block.signatures:
            logger.error("Genesis block has no signatures")
            return False

        root_public_key = public_key_from_b64(self.genesis_block.root_public_key)

        for sig in self.genesis_block.signatures:
            if not verify_model_signature(self.genesis_block, sig, root_public_key):
                logger.error(f"Invalid signature from key {sig.key_id}")
                return False

        logger.info("Genesis block signatures verified successfully")
        return True

    def join_network(self, na_endpoint: str, validity_hours: int = 168) -> JoinCertificate:
        """
        Request a join certificate from the Network Authority.

        Args:
            na_endpoint: Network Authority endpoint (e.g., http://localhost:8443)
            validity_hours: Requested certificate validity in hours

        Returns:
            JoinCertificate from NA

        Raises:
            Exception if join request fails
        """
        logger.info(f"Requesting join certificate from {na_endpoint}")

        # Prepare join request
        request_data = {
            "node_public_key": self.node_keypair.public_key_b64,
            "roles": self.roles,
            "validity_hours": validity_hours
        }

        # Send join request
        try:
            response = requests.post(
                f"{na_endpoint}/join",
                json=request_data,
                timeout=10
            )
            response.raise_for_status()

            # Parse certificate
            cert_data = response.json()
            self.join_certificate = JoinCertificate(**cert_data)

            # Verify certificate signature
            if not self._verify_join_certificate(self.join_certificate):
                raise ValueError("Join certificate signature verification failed")

            logger.info(f"Received valid join certificate: {self.join_certificate.cert_id}")
            logger.info(f"Valid until: {self.join_certificate.expires_at}")

            return self.join_certificate

        except requests.RequestException as e:
            logger.error(f"Join request failed: {e}")
            raise

    def _verify_join_certificate(self, cert: JoinCertificate) -> bool:
        """
        Verify a join certificate signature.

        Args:
            cert: Certificate to verify

        Returns:
            True if certificate is valid
        """
        # Verify network name matches
        if cert.network_name != self.genesis_block.network_name:
            logger.error("Certificate network name mismatch")
            return False

        # Verify certificate is not expired
        if not cert.is_valid():
            logger.error("Certificate is expired or not yet valid")
            return False

        # Verify signature
        na_public_key = public_key_from_b64(self.genesis_block.network_authority.public_key)

        for sig in cert.signatures:
            if verify_model_signature(cert, sig, na_public_key):
                return True

        logger.error("No valid signatures found on certificate")
        return False

    def fetch_policy(self, na_endpoint: str) -> PolicyManifest:
        """
        Fetch and verify the policy manifest from NA.

        Args:
            na_endpoint: Network Authority endpoint

        Returns:
            PolicyManifest

        Raises:
            Exception if fetch or verification fails
        """
        logger.info(f"Fetching policy manifest from {na_endpoint}")

        try:
            response = requests.get(f"{na_endpoint}/policy", timeout=10)
            response.raise_for_status()

            policy_data = response.json()
            self.policy_manifest = PolicyManifest(**policy_data)

            # Verify policy signature
            if not self._verify_policy_manifest(self.policy_manifest):
                raise ValueError("Policy manifest signature verification failed")

            logger.info(f"Received valid policy manifest: {self.policy_manifest.policy_id}")
            return self.policy_manifest

        except requests.RequestException as e:
            logger.error(f"Policy fetch failed: {e}")
            raise

    def _verify_policy_manifest(self, policy: PolicyManifest) -> bool:
        """
        Verify a policy manifest signature.

        Args:
            policy: Policy to verify

        Returns:
            True if policy is valid
        """
        na_public_key = public_key_from_b64(self.genesis_block.network_authority.public_key)

        for sig in policy.signatures:
            if verify_model_signature(policy, sig, na_public_key):
                return True

        logger.error("No valid signatures found on policy manifest")
        return False

    def is_certificate_valid(self) -> bool:
        """
        Check if the current join certificate is valid.

        Returns:
            True if certificate exists and is valid
        """
        if not self.join_certificate:
            return False
        return self.join_certificate.is_valid()

    def get_status(self) -> dict:
        """
        Get node status information.

        Returns:
            Dictionary with node status
        """
        return {
            "network": self.genesis_block.network_name,
            "network_version": self.genesis_block.network_version,
            "node_public_key": self.node_keypair.public_key_b64,
            "roles": self.roles,
            "certificate_valid": self.is_certificate_valid(),
            "certificate_id": self.join_certificate.cert_id if self.join_certificate else None,
            "certificate_expires": self.join_certificate.expires_at.isoformat() if self.join_certificate else None,
            "policy_id": self.policy_manifest.policy_id if self.policy_manifest else None
        }


def main():
    """CLI entry point for mesh node."""
    import argparse

    parser = argparse.ArgumentParser(description='Genesis Mesh Node')
    parser.add_argument('--genesis', required=True, help='Path to signed genesis block JSON')
    parser.add_argument('--node-key', help='Path to node private key (generates new if not provided)')
    parser.add_argument('--bootstrap', required=True, help='Network Authority endpoint for bootstrap')
    parser.add_argument('--role', action='append', dest='roles', help='Node roles (can be specified multiple times)')
    parser.add_argument('--validity-hours', type=int, default=168, help='Certificate validity hours')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Load genesis block
    with open(args.genesis, 'r') as f:
        genesis_data = json.load(f)
        genesis_block = GenesisBlock(**genesis_data)

    # Load or generate node keypair
    node_keypair = None
    if args.node_key:
        private_key = load_private_key(args.node_key)
        node_keypair = KeyPair(private_key=private_key, public_key=private_key.verify_key)
        logger.info(f"Loaded node key from {args.node_key}")
    else:
        logger.info("Generating new node keypair")

    # Set roles
    roles = args.roles or ['role:client']

    # Create node
    node = MeshNode(
        genesis_block=genesis_block,
        node_keypair=node_keypair,
        roles=roles
    )

    # Join network
    try:
        node.join_network(args.bootstrap, args.validity_hours)
        node.fetch_policy(args.bootstrap)

        # Print status
        status = node.get_status()
        print("\n=== Node Status ===")
        for key, value in status.items():
            print(f"{key}: {value}")

        logger.info("Node successfully joined the network")

    except Exception as e:
        logger.error(f"Failed to join network: {e}")
        return 1

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
