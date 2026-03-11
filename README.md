# Schnorr Identification Protocol using Tokio

A simple Rust implementation of **Schnorr's identification protocol** using **Tokio** for asynchronous TCP networking.

## Overview

This project demonstrates a basic **prover-verifier interaction**:

- **Prover**: generates a random scalar $\alpha$, computes the elliptic curve point $R=\alpha G$, and sends it to the verifier.  
- **Verifier**: computes $c\in\mathbb{Z}_q$, and sents it to the prover.
- **Verifier**: receives the point `R` and prints it.  
- The protocol is implemented over **TCP** using **Tokio** for async networking.  
- Command-line control is provided using **Clap**.

## Features

- Asynchronous TCP communication (`tokio::net::TcpListener` / `TcpStream`)  
- Prover generates random values using `k256::Scalar`  
- Elliptic curve operations using `k256` (secp256k1)  
- Command-line subcommands using `clap`  

## Usage

### Start the verifier

```bash
cargo run --bin verifier
