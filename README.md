# Schnorr Identification Protocol using Tokio

A simple Rust implementation of **Schnorr's identification protocol** using **Tokio** for asynchronous TCP networking.

## Overview

This project demonstrates a basic **prover-verifier interaction**:
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

```bash
cargo run --bin verifier
