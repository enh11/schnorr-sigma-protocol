# Schnorr Identification Protocol using Tokio

A simple Rust implementation of **Schnorr's identification protocol** using **Tokio** for asynchronous TCP networking.

## Overview

This project demonstrates a basic prover-verifier interaction:

	
Let $\mathbb{G}$ be a cyclic group of prime order $q$ (in this implementation we use the elliptic curve group k256) with generator $G$. Assume prover $P$ has a secret key $sk=\alpha\in\mathbb{Z}_q$, together with the corresponding public verification key $vk=\alpha G$. Schnorr's identification protocol allows $P$ to convince $V$ that he knows the discrete logarithm of $pk$ to the base $G$, without revealing anything about the secret key $sk$.

- **Prover**: generates a random scalar $\alpha_t$, computes the elliptic curve point $R=\alpha G$, and sends it to the verifier.  
- **Verifier**: computes $c\in\mathbb{Z}_q$, and sents it to the prover.
- **Prover**: computes $\alpha_z\gets \alpha_t + \alpha c\in\mathbb{Z}_q$, and sends $\alpha_z$ to the verifier.
- **Verifier**: checks if $\alpha_z G = R + c G$.

## Features
The protocol is implemented using `tokio` for \emph{Asynchronous TCP communication}. 
Elliptic curve operation from  [`k256`](https://docs.rs/k256/) (secp256k1)  and Command line using `clap`. 

## Usage

### Start the verifier

The verifier opens a TCP listener on `127.0.0.1:8080` and waits for incoming prover connections.

```bash
cargo run --bin verifier
```
### Run the prover
The prover connects to the verifier and sends the commitment 
$R=\alpha_t G$

```
cargo run --bin prover
```

- The server will prompt you for your ID.
  - In this example, we use a `.json` file that maps IDs to public keys.
  - For instance, the ID "123" corresponds to a stored public key.

- After entering the ID, the Schnorr protocol begins:
  - If the prover is honest, the verifier accepts the proof.
  - Otherwise, the verifier rejects the identification attempt.
