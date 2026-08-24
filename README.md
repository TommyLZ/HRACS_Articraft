# HRACS Experimental Artifact

This repository contains the experimental artifact for **HRACS**, including the implementation of the proposed PIR-free asymmetric password-authenticated key exchange (APAKE) design, representative APAKE and portable blind cloud storage (PBCS) baselines, online password-guessing analysis, cryptographic unit benchmarks, and confidential-blockchain storage and retrieval tests.

The artifact supports the performance evaluation reported in the accompanying paper. It is intended for research reproducibility and comparative benchmarking rather than production deployment.

## Repository Structure

```text
.
├── APAKE_Benchmark/
│   ├── APAKE_Chen_PBC/
│   │   ├── Client/
│   │   └── Server/
│   └── APAKE_Yang_PBC/
│       ├── Client/
│       └── Server/
├── APAKE_Communication_Test/
│   ├── Client/
│   └── Server/
├── Blockchain_IO_Test/
├── HRACS/
│   ├── Client/
│   └── Server/
├── OnlinePGA/
├── Operation_UnitTest/
├── PBCS_Benchmark/
│   ├── IPBCS/
│   │   ├── Client/
│   │   └── Server/
│   ├── PHE/
│   │   ├── Client/
│   │   └── Server/
│   └── PLCS/
│       ├── Client/
│       └── Server/
└── README.md
```

| Directory | Purpose |
|---|---|
| `APAKE_Benchmark/` | Computation-overhead benchmarks for representative APAKE constructions used in comparison with the PIR-free APAKE component of HRACS. |
| `APAKE_Communication_Test/` | Client--server experiments, packet analysis, and supporting scripts for measuring APAKE communication overhead over a real network. |
| `Blockchain_IO_Test/` | Solidity contract and JavaScript clients for measuring pseudonym/fingerprint storage and retrieval on the Oasis Sapphire Testnet. |
| `HRACS/` | Client--server implementation of the proposed HRACS scheme, including its PIR-free APAKE component and cloud-storage operations. |
| `OnlinePGA/` | Evaluation of online password-guessing attacks under baseline and pseudonymous rate-limiting settings for several password classes. |
| `Operation_UnitTest/` | Unit benchmarks for dominant cryptographic operations, including hash-to-group, exponentiation, and bilinear pairing. |
| `PBCS_Benchmark/` | Client--server implementations of the PHE, PLCS, and IPBCS baselines used for computation and communication comparisons with HRACS. |

The `Client/` and `Server/` directories contain the host-specific project copies used on the two endpoints of each network experiment.

## Experimental Environment

The reported evaluation used a client--server deployment. The client ran in an Ubuntu 20.04.2 LTS virtual machine with two CPU cores and 8 GB of RAM, hosted on a Windows 11 computer equipped with an Intel Core i7-9750H CPU and 16 GB of RAM. The server ran on a physically separate remote machine, and the endpoints communicated through TCP/IP over a real network.

The principal software configuration was:

- C++17, g++ 11.4.0, and CMake 3.22.1;
- PBC 0.5.14 and OpenSSL 3.0.2;
- GMP, Crypto++, and libsodium where required by the corresponding CMake configuration;
- Solidity 0.8.20, Remix IDE, and MetaMask for blockchain experiments; and
- Oasis Sapphire Testnet (Chain ID `23295`) for confidential smart-contract execution.

Performance measurements are environment-dependent. Comparative experiments should therefore use the same hardware, dependency versions, network conditions, dataset sizes, and repetition counts.

## Building the C++ Components

Most client--server components provide a `CMakeLists.txt` in the relevant `Client/` or `Server/` directory. A typical out-of-source build is:

```bash
cmake -S <component-directory> -B <component-directory>/build
cmake --build <component-directory>/build -j
```

Build the server copy on the remote host and the client copy on the client host. Start the server before the client and configure the endpoint address and port for the deployment environment.

The cryptographic unit benchmark can be compiled directly as follows:

```bash
g++ -std=c++17 -O2 Operation_UnitTest/Operation_Test_Unit.cpp \
  -o operation_unit_test -lpbc -lgmp
./operation_unit_test
```

The blockchain contract can be compiled and deployed with Solidity 0.8.20 through Remix. The JavaScript read/write scripts are intended to run in a browser environment with MetaMask connected to the Oasis Sapphire Testnet. Update the configured contract address before executing the scripts. Testnet transactions may consume test tokens.

## Datasets and Evaluation Scope

The online password-guessing evaluation uses four password datasets of 20,000 entries each: 6-digit passwords, 12-character passwords, passwords of length 6--12, and 3--6-word passphrases. The evaluation draws on the [password corpora](https://www.kaggle.com/datasets/anonymous4open/password-corpora), the [RockYou wordlist](https://weakpass.com/wordlists/rockyou.txt), and the [EFF Large Wordlist](https://www.eff.org/document/passphrase-wordlists).

The HRACS storage evaluation uses 600 individual 1 MB files from the [benchmark dataset](https://www.kaggle.com/datasets/anonymous4open/benchmark-dataset). Large external datasets are not bundled with this repository and should be obtained from their respective sources.

The artifact covers the following evaluation dimensions:

1. robustness of PIR-free APAKE against online password guessing;
2. APAKE computation and communication overhead;
3. HRACS computation and communication overhead relative to PHE, PLCS, and IPBCS;
4. unit costs of dominant cryptographic operations; and
5. latency, gas consumption, and monetary cost of confidential-blockchain storage and retrieval.

## Reproducibility Notes

- Run each benchmark with the repetition count reported in the paper and report aggregate statistics rather than a single execution.
- Preserve the client/server placement and network topology when reproducing communication measurements.
- Record compiler, library, operating-system, and blockchain-network versions with each result.
