                             
                                      
                                              
                                                     
                              
                                        
                                
                                  
                                    

async function runLatencyGasTest(NUM_RUNS = 15) {

                                                   

                                                  
  const CONTRACT_ADDRESS =
    "0xCD7c993CF5396930bAA178fC8faE7C2AB443Ad90";

                           
  const EXPECTED_CHAIN_ID = 23295n;
  const EXPECTED_CHAIN_ID_HEX = "0x5aff";

  const PSEUDONYM_BYTES = 18;                 
  const FINGERPRINT_BYTES = 128;               
  const CONFIRMATIONS = 1;

                                     
  const GAS_LIMIT = 500000n;

                        
  const VERIFY_AFTER_WRITE = true;

  if (!Number.isInteger(NUM_RUNS) || NUM_RUNS <= 0) {
    throw new Error("NUM_RUNS must be an integer greater than 0");
  }

                                                                

  const discoveredProviders = [];

  function handleAnnounceProvider(event) {
    if (event?.detail) {
      discoveredProviders.push(event.detail);
    }
  }

  window.addEventListener(
    "eip6963:announceProvider",
    handleAnnounceProvider
  );

  window.dispatchEvent(
    new Event("eip6963:requestProvider")
  );

  await new Promise(resolve => setTimeout(resolve, 500));

  window.removeEventListener(
    "eip6963:announceProvider",
    handleAnnounceProvider
  );

  console.log(
    "Detected wallets: ",
    discoveredProviders.map(item => ({
      name: item.info?.name,
      rdns: item.info?.rdns
    }))
  );

  let ethereumProvider = null;

  const metamaskEntry = discoveredProviders.find(item => {
    const name = item.info?.name?.toLowerCase() || "";
    const rdns = item.info?.rdns?.toLowerCase() || "";

    return (
      rdns === "io.metamask" ||
      name.includes("metamask")
    );
  });

  if (metamaskEntry) {
    ethereumProvider = metamaskEntry.provider;
    console.log("✅ Selected MetaMask via EIP-6963");

  } else if (Array.isArray(window.ethereum?.providers)) {
    ethereumProvider = window.ethereum.providers.find(
      item => item.isMetaMask
    );

    if (ethereumProvider) {
      console.log(
        "✅ Selected MetaMask via window.ethereum.providers"
      );
    }

  } else if (window.ethereum?.isMetaMask) {
    ethereumProvider = window.ethereum;
    console.log("✅ Selected MetaMask via window.ethereum");
  }

  if (!ethereumProvider) {
    throw new Error(
      "❌ MetaMask was not detected. Confirm that MetaMask is installed and enabled"
    );
  }

                                                                           

  const ethers = await import(
    "https://cdn.jsdelivr.net/npm/ethers@6.13.0/+esm"
  );

  const sapphire = await import(
    "https://cdn.jsdelivr.net/npm/@oasisprotocol/sapphire-paratime/+esm"
  );

  const contractAddress = ethers.getAddress(CONTRACT_ADDRESS);

                                                         

  const currentChainIdHex = await ethereumProvider.request({
    method: "eth_chainId"
  });

  const currentChainId = BigInt(currentChainIdHex);

  console.log(
    "Current MetaMask chain ID: ",
    `${currentChainId.toString()} (${currentChainIdHex})`
  );

  if (currentChainId !== EXPECTED_CHAIN_ID) {
    throw new Error(
      `❌ The current MetaMask network is incorrect.` +
      ` Expected Sapphire Testnet: ${EXPECTED_CHAIN_ID.toString()} ` +
      `(${EXPECTED_CHAIN_ID_HEX}), ` +
      `Actual ${currentChainId.toString()} (${currentChainIdHex}).` +
      ` Switch networks and run the script again.`
    );
  }

                                                                            

                                    
  await ethereumProvider.request({
    method: "eth_requestAccounts"
  });

                                                    
  const wrappedEthereumProvider =
    sapphire.wrapEthereumProvider(ethereumProvider);

  const provider =
    new ethers.BrowserProvider(wrappedEthereumProvider);

  const signer = await provider.getSigner();
  const signerAddress = await signer.getAddress();

  console.log("Current signing account: ", signerAddress);
  console.log("Target contract address: ", contractAddress);

  const balance = await provider.getBalance(signerAddress);

  console.log(
    "Current account balance: ",
    `${ethers.formatEther(balance)} TEST`
  );

                         
  const contractCode = await provider.getCode(contractAddress);

  if (contractCode === "0x") {
    throw new Error(
      `❌ Address ${contractAddress} has no contract code on the current network.` +
      ` Verify the contract address and MetaMask network.`
    );
  }

  console.log(
    "✅ Confirmed that the target address contains contract code; code length: ",
    `${(contractCode.length - 2) / 2} bytes`
  );

                                                            

[
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes18",
        "name": "pseudonym",
        "type": "bytes18"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "name": "PseudonymUpdated",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "bytes18",
        "name": "_newPseudonym",
        "type": "bytes18"
      },
      {
        "internalType": "bytes",
        "name": "_fingerprint",
        "type": "bytes"
      }
    ],
    "name": "updatePseudonym",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes18",
        "name": "_pseudonym",
        "type": "bytes18"
      }
    ],
    "name": "getPseudonymData",
    "outputs": [
      {
        "internalType": "bytes18",
        "name": "pseudonym",
        "type": "bytes18"
      },
      {
        "internalType": "bytes",
        "name": "fingerprint",
        "type": "bytes"
      },
      {
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes18",
        "name": "",
        "type": "bytes18"
      }
    ],
    "name": "pseudonymRegistry",
    "outputs": [
      {
        "internalType": "bytes18",
        "name": "pseudonym",
        "type": "bytes18"
      },
      {
        "internalType": "bytes",
        "name": "fingerprint",
        "type": "bytes"
      },
      {
        "internalType": "uint256",
        "name": "timestamp",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
]

                                                   

  function randomHex(bytesLength) {
    return ethers.hexlify(
      ethers.randomBytes(bytesLength)
    );
  }

  function mean(values) {
    if (values.length === 0) {
      return NaN;
    }

    return values.reduce(
      (sum, value) => sum + value,
      0
    ) / values.length;
  }

                     
  function sampleStdDev(values) {
    if (values.length <= 1) {
      return 0;
    }

    const average = mean(values);

    const variance = values.reduce(
      (sum, value) =>
        sum + Math.pow(value - average, 2),
      0
    ) / (values.length - 1);

    return Math.sqrt(variance);
  }

  function percentile(values, ratio) {
    if (values.length === 0) {
      return NaN;
    }

    const sorted = [...values].sort((a, b) => a - b);
    const position = (sorted.length - 1) * ratio;
    const lowerIndex = Math.floor(position);
    const upperIndex = Math.ceil(position);

    if (lowerIndex === upperIndex) {
      return sorted[lowerIndex];
    }

    const weight = position - lowerIndex;

    return (
      sorted[lowerIndex] * (1 - weight) +
      sorted[upperIndex] * weight
    );
  }

  function escapeCsv(value) {
    const text =
      value === null || value === undefined
        ? ""
        : String(value);

    if (
      text.includes(",") ||
      text.includes('"') ||
      text.includes("\n") ||
      text.includes("\r")
    ) {
      return `"${text.replace(/"/g, '""')}"`;
    }

    return text;
  }

  function getErrorDetails(error) {
    return {
      name: error?.name ?? "",
      code: error?.code ?? "",
      shortMessage: error?.shortMessage ?? "",
      message: error?.message ?? String(error),
      reason: error?.reason ?? "",
      action: error?.action ?? "",
      data: error?.data ?? "",
      transaction: error?.transaction ?? "",
      invocation: error?.invocation ?? "",
      rpcError: error?.info?.error ?? "",
      payload: error?.info?.payload ?? "",
      cause: error?.cause ?? ""
    };
  }

  function formatError(error) {
    const rpcMessage =
      error?.info?.error?.message ||
      error?.info?.error?.data?.message;

    return (
      rpcMessage ||
      error?.shortMessage ||
      error?.reason ||
      error?.message ||
      String(error)
    );
  }

  function printFullError(title, error) {
    console.error(title, error);
    console.error("Complete error fields: ", getErrorDetails(error));
  }

                                                         

  console.log("\n========== Contract Interface Preflight Check ==========");

  console.log(
    "getPseudonymData selector: ",
    contract.interface.getFunction(
      "getPseudonymData"
    ).selector
  );

  console.log(
    "pseudonymRegistry selector: ",
    contract.interface.getFunction(
      "pseudonymRegistry"
    ).selector
  );

  console.log(
    "updatePseudonym selector: ",
    contract.interface.getFunction(
      "updatePseudonym"
    ).selector
  );

  const ZERO_PSEUDONYM =
    "0x000000000000000000000000000000000000";

                   
  try {
    const result = await contract.getPseudonymData(
      ZERO_PSEUDONYM
    );

    console.log(
      "✅ getPseudonymData call succeeded: ",
      {
        pseudonym: result[0],
        fingerprint: result[1],
        timestamp: result[2].toString()
      }
    );

  } catch (error) {
    printFullError(
      "❌ getPseudonymData preflight check failed: ",
      error
    );

    throw new Error(
      "Contract preflight check failed: getPseudonymData could not be called." +
      " This usually means that the address does not match the ABI, the deployment network is incorrect, or the Sapphire call is not wrapped correctly."
    );
  }

                                         
  try {
    const result = await contract.pseudonymRegistry(
      ZERO_PSEUDONYM
    );

    console.log(
      "✅ pseudonymRegistry call succeeded: ",
      {
        pseudonym: result[0],
        fingerprint: result[1],
        timestamp: result[2].toString()
      }
    );

  } catch (error) {
    printFullError(
      "❌ pseudonymRegistry preflight check failed: ",
      error
    );

    throw new Error(
      "Contract preflight check failed: pseudonymRegistry could not be called." +
      " Confirm that the deployment address corresponds to this PseudonymManager contract."
    );
  }

                                           
  try {
    const testPseudonym = randomHex(PSEUDONYM_BYTES);
    const testFingerprint = randomHex(FINGERPRINT_BYTES);

    await contract.updatePseudonym.staticCall(
      testPseudonym,
      testFingerprint
    );

    console.log(
      "✅ updatePseudonym.staticCall succeeded; the write interface and parameter format are valid"
    );

  } catch (error) {
    printFullError(
      "❌ updatePseudonym.staticCall preflight check failed: ",
      error
    );

    throw new Error(
      "Contract preflight check failed: the updatePseudonym simulation reverted." +
      " Check the ABI, contract address, and deployed Solidity code."
    );
  }

  console.log("✅ All interface preflight checks passed; starting the batch write test");

                                                            

  const generatedPseudonyms = new Set();

  async function generateUnusedPseudonym() {
    const MAX_ATTEMPTS = 10;

    for (
      let attempt = 1;
      attempt <= MAX_ATTEMPTS;
      attempt++
    ) {
      const pseudonym = randomHex(PSEUDONYM_BYTES);
      const normalized = pseudonym.toLowerCase();

      if (generatedPseudonyms.has(normalized)) {
        continue;
      }

      const storedData =
        await contract.getPseudonymData(pseudonym);

      const storedTimestamp = storedData[2];

                                    
      if (storedTimestamp === 0n) {
        generatedPseudonyms.add(normalized);
        return pseudonym;
      }

      console.warn(
        `The random pseudonym already exists; regenerating: ${pseudonym}`,
        {
          storedPseudonym: storedData[0],
          fingerprintBytes:
            ethers.getBytes(storedData[1]).length,
          timestamp: storedTimestamp.toString()
        }
      );
    }

    throw new Error(
      "Repeatedly generated pseudonyms already exist; a new test pseudonym could not be generated"
    );
  }

                                                       

  const results = [];

  console.log(
    `\nStarting ${NUM_RUNS} initial-write tests`
  );

  console.log(
    `Each write: ${PSEUDONYM_BYTES}-byte pseudonym + ` +
    `${FINGERPRINT_BYTES} bytes fingerprint`
  );

  console.log(
    "Note: wallet submission latency includes the time spent manually confirming in MetaMask."
  );

  for (let i = 0; i < NUM_RUNS; i++) {

    console.log(
      `\n========== Run ${i + 1}/${NUM_RUNS} ==========`
    );

    let pseudonym = "";
    let fingerprint = "";

    let txHash = "";
    let blockNumber = "";

    let walletSubmissionLatencyMs = "";
    let confirmationLatencyS = "";
    let totalLatencyS = "";

    let gasUsedString = "";
    let gasPriceGwei = "";
    let feeNativeToken = "";

    let storedPseudonym = "";
    let storedFingerprint = "";
    let storedFingerprintBytes = "";
    let storedTimestamp = "";

    let pseudonymMatches = false;
    let fingerprintMatches = false;
    let fingerprintLengthValid = false;
    let verified = false;

    let verificationError = "";
    let transactionError = "";
    let errorCode = "";
    let errorAction = "";
    let errorData = "";

    try {
      pseudonym = await generateUnusedPseudonym();
      fingerprint = randomHex(FINGERPRINT_BYTES);

      const pseudonymBytes =
        ethers.getBytes(pseudonym).length;

      const fingerprintBytes =
        ethers.getBytes(fingerprint).length;

      if (pseudonymBytes !== PSEUDONYM_BYTES) {
        throw new Error(
          `Invalid pseudonym length: expected ${PSEUDONYM_BYTES} bytes, ` +
          `actual ${pseudonymBytes} bytes`
        );
      }

      if (fingerprintBytes !== FINGERPRINT_BYTES) {
        throw new Error(
          `Invalid fingerprint length: expected ` +
          `${FINGERPRINT_BYTES} bytes, actual ${fingerprintBytes} bytes`
        );
      }

      console.log("pseudonym: ", pseudonym);
      console.log(
        "fingerprint length: ",
        `${fingerprintBytes} bytes`
      );

                                 
      try {
        await contract.updatePseudonym.staticCall(
          pseudonym,
          fingerprint
        );
      } catch (simError) {
        printFullError(
          `❌ Run ${i + 1} staticCall failed: `,
          simError
        );

        throw new Error(
          `Dry-run call failed; the contract would revert: ${formatError(simError)}`
        );
      }

      const submissionStart = performance.now();

      const tx = await contract.updatePseudonym(
        pseudonym,
        fingerprint,
        {
          gasLimit: GAS_LIMIT
        }
      );

      const submissionEnd = performance.now();

      walletSubmissionLatencyMs =
        submissionEnd - submissionStart;

      txHash = tx.hash;

      console.log("tx hash: ", txHash);
      console.log(
        "Wallet submission latency: ",
        `${walletSubmissionLatencyMs.toFixed(2)} ms`
      );

      const confirmationStart = performance.now();
      const receipt = await tx.wait(CONFIRMATIONS);
      const confirmationEnd = performance.now();

      if (!receipt) {
        throw new Error("tx.wait() did not return a transaction receipt");
      }

      confirmationLatencyS =
        (confirmationEnd - confirmationStart) / 1000;

      totalLatencyS =
        (confirmationEnd - submissionStart) / 1000;

      if (
        receipt.status !== null &&
        receipt.status !== 1
      ) {
        throw new Error(
          `Transaction execution failed, receipt.status=${receipt.status}`
        );
      }

      blockNumber = receipt.blockNumber;

      const gasUsed = receipt.gasUsed;

      const actualGasPrice =
        receipt.gasPrice ??
        tx.gasPrice;

      if (
        actualGasPrice === null ||
        actualGasPrice === undefined
      ) {
        throw new Error(
          "The transaction receipt has no gasPrice; the fee cannot be calculated"
        );
      }

      const feeWei = gasUsed * actualGasPrice;

      gasUsedString = gasUsed.toString();

      gasPriceGwei = ethers.formatUnits(
        actualGasPrice,
        "gwei"
      );

      feeNativeToken = ethers.formatEther(feeWei);

      console.log(
        "Confirmation latency: ",
        `${confirmationLatencyS.toFixed(2)} s`
      );

      console.log(
        "Total latency: ",
        `${totalLatencyS.toFixed(2)} s`
      );

      console.log("Block: ", blockNumber);
      console.log("Gas used: ", gasUsedString);
      console.log("Gas price: ", `${gasPriceGwei} gwei`);
      console.log(
        "Fee: ",
        `${feeNativeToken} native token`
      );

                                                        

      if (VERIFY_AFTER_WRITE) {
        try {
          const storedData =
            await contract.getPseudonymData(pseudonym);

          storedPseudonym = storedData[0];
          storedFingerprint = storedData[1];
          storedTimestamp = storedData[2].toString();

          storedFingerprintBytes =
            ethers.getBytes(storedFingerprint).length;

          pseudonymMatches =
            storedPseudonym.toLowerCase() ===
            pseudonym.toLowerCase();

          fingerprintMatches =
            storedFingerprint.toLowerCase() ===
            fingerprint.toLowerCase();

          fingerprintLengthValid =
            storedFingerprintBytes ===
            FINGERPRINT_BYTES;

          verified =
            pseudonymMatches &&
            fingerprintMatches &&
            fingerprintLengthValid &&
            storedData[2] !== 0n;

          console.log(
            "Stored pseudonym: ",
            storedPseudonym
          );

          console.log(
            "Stored fingerprint length: ",
            `${storedFingerprintBytes} bytes`
          );

          console.log(
            "Stored timestamp: ",
            storedTimestamp
          );

          if (verified) {
            console.log(
              "✅ Write verification succeeded: the pseudonym and 128-byte fingerprint were written"
            );
          } else {
            console.warn(
              "⚠️ The write transaction was confirmed, but on-chain data verification failed",
              {
                pseudonymMatches,
                fingerprintMatches,
                fingerprintLengthValid,
                storedTimestamp
              }
            );
          }

        } catch (error) {
          verificationError = formatError(error);

          printFullError(
            "⚠️ The transaction was confirmed, but the subsequent read verification failed: ",
            error
          );
        }

      } else {
        verified = true;
      }

    } catch (error) {
      transactionError = formatError(error);
      errorCode = error?.code ?? "";
      errorAction = error?.action ?? "";
      errorData = error?.data ?? "";

      printFullError(
        `❌ Run ${i + 1} failed: `,
        error
      );
    }

    results.push({
      run: i + 1,

      pseudonym,
      fingerprint,
      fingerprintBytes:
        fingerprint
          ? ethers.getBytes(fingerprint).length
          : "",

      txHash,
      block: blockNumber,

      walletSubmissionLatencyMs:
        typeof walletSubmissionLatencyMs === "number"
          ? walletSubmissionLatencyMs
          : "",

      confirmationLatencyS:
        typeof confirmationLatencyS === "number"
          ? confirmationLatencyS
          : "",

      totalLatencyS:
        typeof totalLatencyS === "number"
          ? totalLatencyS
          : "",

      gasUsed: gasUsedString,
      gasPriceGwei,
      feeNativeToken,

      storedPseudonym,
      storedFingerprint,
      storedFingerprintBytes,
      storedTimestamp,

      pseudonymMatches,
      fingerprintMatches,
      fingerprintLengthValid,
      verified,

      verificationError,
      error: transactionError,
      errorCode,
      errorAction,
      errorData
    });
  }

                                                       

  const successfulTransactions = results.filter(result =>
    !result.error &&
    result.txHash &&
    result.gasUsed
  );

  const verifiedResults = successfulTransactions.filter(
    result => result.verified
  );

  console.log(
    "\n========== Write Test Summary =========="
  );

  console.log(
    `Successful transactions: ${successfulTransactions.length} / ${NUM_RUNS}`
  );

  console.log(
    `Successful write verifications: ${verifiedResults.length} / ${NUM_RUNS}`
  );

  if (successfulTransactions.length === 0) {
    console.warn(
      "No transactions succeeded; statistics cannot be calculated."
    );

  } else {
    const submissionLatencies =
      successfulTransactions.map(
        result => Number(result.walletSubmissionLatencyMs)
      );

    const confirmationLatencies =
      successfulTransactions.map(
        result => Number(result.confirmationLatencyS)
      );

    const totalLatencies =
      successfulTransactions.map(
        result => Number(result.totalLatencyS)
      );

    const gasUsedValues =
      successfulTransactions.map(
        result => Number(result.gasUsed)
      );

    const gasPriceValues =
      successfulTransactions.map(
        result => Number(result.gasPriceGwei)
      );

    const feeValues =
      successfulTransactions.map(
        result => Number(result.feeNativeToken)
      );

    console.log(
      "\nWallet submission latency (ms): "
    );

    console.log(
      `mean=${mean(submissionLatencies).toFixed(2)}, ` +
      `sample standard deviation=${sampleStdDev(submissionLatencies).toFixed(2)}, ` +
      `min=${Math.min(...submissionLatencies).toFixed(2)}, ` +
      `max=${Math.max(...submissionLatencies).toFixed(2)}`
    );

    console.log("\nConfirmation latency (s): ");

    console.log(
      `mean=${mean(confirmationLatencies).toFixed(2)}, ` +
      `sample standard deviation=${sampleStdDev(confirmationLatencies).toFixed(2)}, ` +
      `min=${Math.min(...confirmationLatencies).toFixed(2)}, ` +
      `max=${Math.max(...confirmationLatencies).toFixed(2)}, ` +
      `P50=${percentile(confirmationLatencies, 0.50).toFixed(2)}, ` +
      `P95=${percentile(confirmationLatencies, 0.95).toFixed(2)}`
    );

    console.log("\nTotal latency (s): ");

    console.log(
      `mean=${mean(totalLatencies).toFixed(2)}, ` +
      `sample standard deviation=${sampleStdDev(totalLatencies).toFixed(2)}`
    );

    console.log("\nGas used: ");

    console.log(
      `mean=${mean(gasUsedValues).toFixed(0)}, ` +
      `sample standard deviation=${sampleStdDev(gasUsedValues).toFixed(0)}, ` +
      `min=${Math.min(...gasUsedValues).toFixed(0)}, ` +
      `max=${Math.max(...gasUsedValues).toFixed(0)}`
    );

    console.log("\nGas price (gwei): ");

    console.log(
      `mean=${mean(gasPriceValues).toFixed(6)}, ` +
      `sample standard deviation=${sampleStdDev(gasPriceValues).toFixed(6)}`
    );

    console.log("\nFee (native token): ");

    console.log(
      `mean=${mean(feeValues).toFixed(10)}, ` +
      `sample standard deviation=${sampleStdDev(feeValues).toFixed(10)}`
    );
  }

                                                         

  window.__WRITE_KEYS = verifiedResults.map(
    result => result.pseudonym
  );

  window.__WRITE_RECORDS = verifiedResults.map(
    result => ({
      pseudonym: result.pseudonym,
      fingerprint: result.fingerprint,
      timestamp: result.storedTimestamp,
      txHash: result.txHash,
      block: result.block
    })
  );

  window.__testResults = results;

  console.log(
    `\n✅ Saved ${window.__WRITE_KEYS.length} valid pseudonyms to window.__WRITE_KEYS`
  );

  console.log(
    "✅ Complete test records saved to window.__testResults"
  );

  console.log(
    "✅ Write records and fingerprints saved to window.__WRITE_RECORDS"
  );

                                                          

  const columns = [
    "run",
    "pseudonym",
    "fingerprint",
    "fingerprintBytes",
    "txHash",
    "block",
    "walletSubmissionLatencyMs",
    "confirmationLatencyS",
    "totalLatencyS",
    "gasUsed",
    "gasPriceGwei",
    "feeNativeToken",
    "storedPseudonym",
    "storedFingerprint",
    "storedFingerprintBytes",
    "storedTimestamp",
    "pseudonymMatches",
    "fingerprintMatches",
    "fingerprintLengthValid",
    "verified",
    "verificationError",
    "error",
    "errorCode",
    "errorAction",
    "errorData"
  ];

  const csvRows = [
    columns.join(","),
    ...results.map(result =>
      columns.map(column => {
        let value = result[column];

        if (
          column === "walletSubmissionLatencyMs" &&
          typeof value === "number"
        ) {
          value = value.toFixed(2);
        }

        if (
          (
            column === "confirmationLatencyS" ||
            column === "totalLatencyS"
          ) &&
          typeof value === "number"
        ) {
          value = value.toFixed(4);
        }

        if (
          typeof value === "object" &&
          value !== null
        ) {
          try {
            value = JSON.stringify(value);
          } catch {
            value = String(value);
          }
        }

        return escapeCsv(value);
      }).join(",")
    )
  ];

  const csvContent =
    "\uFEFF" + csvRows.join("\n");

  const blob = new Blob(
    [csvContent],
    {
      type: "text/csv;charset=utf-8"
    }
  );

  const downloadUrl = URL.createObjectURL(blob);
  const downloadLink = document.createElement("a");

  downloadLink.href = downloadUrl;
  downloadLink.download =
    "pseudonym_fingerprint_write_results.csv";

  document.body.appendChild(downloadLink);
  downloadLink.click();
  downloadLink.remove();

  setTimeout(
    () => URL.revokeObjectURL(downloadUrl),
    1000
  );

  console.log(
    "\n✅ CSV download triggered: pseudonym_fingerprint_write_results.csv"
  );

  return results;
}

             
runLatencyGasTest(15).catch(error => {
  console.error("\n❌ Test script terminated: ", error);
  console.error("See the first complete error message above." );
});
