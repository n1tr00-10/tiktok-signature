# TikTok Signature Generator

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Stars](https://img.shields.io/github/stars/tiktok-signature/tiktok-signature)
![Forks](https://img.shields.io/github/forks/tiktok-signature/tiktok-signature)
![Issues](https://img.shields.io/github/issues/tiktok-signature/tiktok-signature)

Generate valid **X-Gnarly**, **X-Bogus**, and **X-Dynosaur** signatures for TikTok Web API requests.

Supports SDK version **5.1.2** (build 1.0.0.316).

## Features

- Generate X-Gnarly signatures with ChaCha20 encryption and dynamic round selection
- Generate X-Bogus signatures with RC4 encryption and custom Base64 encoding
- Generate X-Dynosaur signatures with ChaCha20 encryption and FNV-1a hashing
- Support for SDK version 5.1.2 (build 1.0.0.316)
- Pure Python implementation
- Lightweight and production-ready

## Installation

```bash
git clone https://github.com/tiktok-signature/tiktok-signature.git
cd tiktok-signature
