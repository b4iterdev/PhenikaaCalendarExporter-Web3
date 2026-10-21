# Web3 Architecture & Integration Guide

`PhenikaaCalendarExporter-Web3` transforms the calendar exporter into a Web3-native dApp architecture while retaining compatibility with upstream core features.

## Core Web3 Components

### 1. Decentralized Identity: Sign-In with Ethereum (SIWE / EIP-4361)
- **Authentication**: Replaces centralized Google/OIDC accounts with Ethereum & EVM wallet signatures.
- **Protocol**: EIP-4361 standard.
- **Endpoints**:
  - `GET /auth/siwe/nonce`: Issues a cryptographic random nonce in a short-lived HTTP-only signed session.
  - `POST /auth/siwe/verify`: Receives SIWE message + signature, recovers public address using `web3.py` & `eth-account`, checks nonce/domain match, and initializes user session under `eth:<wallet_address>`.
- **Supported Wallets**: MetaMask, Rabby, Rainbow, Coinbase Wallet, WalletConnect, or any EIP-1193 browser provider.

### 2. Decentralized Storage: IPFS Pinning
- **Storage**: Calendar artifacts (`calendar.json`, `calendar.ics`, `calendar.xlsx`) are pinned directly to IPFS.
- **Provider**: Automated integration with Pinata via `PINATA_JWT`. When unconfigured, a deterministic CIDv1 generator is used locally for testing.
- **Access**:
  - Web UI displays persistent `ipfs://<CID>` links for each session.
  - REST API `GET /api/v1/sessions/{id}/exports` includes an `ipfs` object with `cid`, `url`, and `uri`.

### 3. On-Chain Token Gating & VIP Tiers
- **Contract Verification**: Reads ERC-20 / ERC-721 token balances via smart contract calls using EVM JSON-RPC (`WEB3_RPC_URL`).
- **Access Gating**: Restricts API v1 endpoints to wallets holding required token balances when `TOKEN_GATE_CONTRACT` and `TOKEN_GATE_MIN_BALANCE` are set.
- **EVM Networks**: Compatible with Polygon, Arbitrum, Base, Ethereum Mainnet, and EVM testnets.

---

## Configuration Reference

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `PHENIKAA_SERVER_AUTH` | Authentication mode (`web3`, `google`, `oidc`, or `disabled`) | `web3` |
| `WEB3_RPC_URL` | EVM JSON-RPC endpoint for chain queries | `https://polygon-rpc.com` |
| `WEB3_CHAIN_ID` | Target blockchain chain ID (e.g. 137 for Polygon) | `137` |
| `PINATA_JWT` | Pinata API JWT for pinning calendar files to IPFS | `""` (mock fallback) |
| `IPFS_GATEWAY` | IPFS gateway for public download URLs | `https://gateway.pinata.cloud/ipfs/` |
| `TOKEN_GATE_CONTRACT` | ERC-20 / NFT contract address for gated API usage | `""` (disabled) |
| `TOKEN_GATE_MIN_BALANCE` | Minimum token balance required for gated access | `0` |
