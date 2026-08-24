                             
                                                         
                             
                                   
                                                    
                  
              
                                                 
                            
                                   

async function runReadLatencyTest(NUM_RUNS = 15) {

                                           
  const ethers = await import(
    "https://cdn.jsdelivr.net/npm/ethers@6.13.0/+esm"
  );

                                   

                                                            
  const contractAddr =
    "0xc10F26fEC5455CBC9E880946719A0309BAd81332";

  const RPC_URL =
    "https://testnet.sapphire.oasis.io";

  const EXPECTED_CHAIN_ID = 23295n;
  const EXPECTED_FINGERPRINT_BYTES = 128;
  const WARMUP_RUNS = 3;

                                   
  const abi = [
    {
      name: "getPseudonymData",
      type: "function",
      inputs: [
        {
          name: "_pseudonym",
          type: "bytes18"
        }
      ],
      outputs: [
        {
          name: "pseudonym",
          type: "bytes18"
        },
        {
          name: "fingerprint",
          type: "bytes"
        },
        {
          name: "timestamp",
          type: "uint256"
        }
      ],
      stateMutability: "view"
    }
  ];

                                    
  const provider = new ethers.JsonRpcProvider(RPC_URL);

                                      
  const network = await provider.getNetwork();

  console.log(
    `Connected chain ID: ${network.chainId.toString()}`
  );

  if (network.chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(
      `Network error: expected Sapphire Testnet chain ID ` +
      `${EXPECTED_CHAIN_ID.toString()}, actual ` +
      `${network.chainId.toString()}`
    );
  }

                       
  const contractCode = await provider.getCode(contractAddr);

  if (contractCode === "0x") {
    throw new Error(
      `Address ${contractAddr} has no contract code on the current network. ` +
      `Check the contract address and network.`
    );
  }

  const contract = new ethers.Contract(
    contractAddr,
    abi,
    provider
  );

                                        
  function extractPseudonym(item) {
    if (typeof item === "string") {
      return item;
    }

    if (item && typeof item === "object") {
      return item.pseudonym || item.key || null;
    }

    return null;
  }

  function isValidBytes18(value) {
    return (
      typeof value === "string" &&
      /^0x[0-9a-fA-F]{36}$/.test(value)
    );
  }

  const candidateItems = [];

                                    
  if (
    Array.isArray(window.__WRITE_KEYS) &&
    window.__WRITE_KEYS.length > 0
  ) {
    candidateItems.push(...window.__WRITE_KEYS);
  }

                            
  if (
    Array.isArray(window.__testResults) &&
    window.__testResults.length > 0
  ) {
    candidateItems.push(
      ...window.__testResults.filter(item => !item?.error)
    );
  }

  const validPseudonyms = [
    ...new Set(
      candidateItems
        .map(extractPseudonym)
        .filter(isValidBytes18)
        .map(value => value.toLowerCase())
    )
  ];

  if (validPseudonyms.length === 0) {
    throw new Error(
      "No actual written pseudonyms were detected. Run the write test first, " +
      "and ensure that the write script saved window.__WRITE_KEYS " +
      "or window.__testResults."
    );
  }

  console.log(
    `✅ Detected ${validPseudonyms.length} actual written pseudonyms`
  );

                            
  const keysToRead = [];

  for (let i = 0; i < NUM_RUNS; i++) {
    keysToRead.push(
      validPseudonyms[i % validPseudonyms.length]
    );
  }

                                 
  console.log(
    `Running ${WARMUP_RUNS} warm-up reads; warm-up results are excluded from statistics...`
  );

  for (let i = 0; i < WARMUP_RUNS; i++) {
    await contract.getPseudonymData(keysToRead[0]);
  }

  console.log("✅ Warm-up complete");

                                   
  function mean(values) {
    return (
      values.reduce((sum, value) => sum + value, 0) /
      values.length
    );
  }

                    
  function sampleStdDev(values) {
    if (values.length <= 1) {
      return 0;
    }

    const average = mean(values);

    const variance =
      values.reduce(
        (sum, value) =>
          sum + Math.pow(value - average, 2),
        0
      ) /
      (values.length - 1);

    return Math.sqrt(variance);
  }

  function percentile(values, ratio) {
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

                                   
  const results = [];

  for (let i = 0; i < NUM_RUNS; i++) {
    const key = keysToRead[i];

    console.log(
      `\n--- Read ${i + 1}/${NUM_RUNS} ---`
    );
    console.log(`key: ${key}`);

    try {
      const startTime = performance.now();

      const [
        returnedPseudonym,
        fingerprint,
        timestamp
      ] = await contract.getPseudonymData(key);

      const endTime = performance.now();

      const latencyMs = endTime - startTime;
      const fingerprintBytes =
        ethers.getBytes(fingerprint).length;

      const isEmpty = timestamp === 0n;

      const pseudonymMatches =
        returnedPseudonym.toLowerCase() ===
        key.toLowerCase();

      const fingerprintLengthValid =
        fingerprintBytes ===
        EXPECTED_FINGERPRINT_BYTES;

      console.log(
        `latency: ${latencyMs.toFixed(2)} ms`
      );

      console.log(
        `returned pseudonym: ${returnedPseudonym}`
      );

      console.log(
        `fingerprint length: ${fingerprintBytes} bytes`
      );

      console.log(
        `timestamp: ${timestamp.toString()}`
      );

      if (isEmpty) {
        console.warn(
          "⚠️ The current key maps to an empty record"
        );
      }

      if (!isEmpty && !pseudonymMatches) {
        console.warn(
          "⚠️ The returned pseudonym does not match the query key"
        );
      }

      if (
        !isEmpty &&
        !fingerprintLengthValid
      ) {
        console.warn(
          `⚠️ fingerprint length is not ` +
          `${EXPECTED_FINGERPRINT_BYTES} bytes`
        );
      }

      results.push({
        run: i + 1,
        key,
        returnedPseudonym,
        latencyMs,
        fingerprint,
        fingerprintBytes,
        timestamp: timestamp.toString(),
        isEmpty,
        pseudonymMatches,
        fingerprintLengthValid,
        error: ""
      });

    } catch (error) {
      const errorMessage =
        error?.shortMessage ||
        error?.message ||
        String(error);

      console.error(
        `Read ${i + 1} failed:`,
        errorMessage
      );

      results.push({
        run: i + 1,
        key,
        returnedPseudonym: "",
        latencyMs: "",
        fingerprint: "",
        fingerprintBytes: "",
        timestamp: "",
        isEmpty: "",
        pseudonymMatches: "",
        fingerprintLengthValid: "",
        error: errorMessage
      });
    }
  }

                                   
  const successResults = results.filter(
    result => !result.error
  );

  const validResults = successResults.filter(
    result =>
      !result.isEmpty &&
      result.pseudonymMatches &&
      result.fingerprintLengthValid
  );

  if (successResults.length === 0) {
    console.warn(
      "No reads completed successfully; statistics cannot be calculated."
    );

    window.__readTestResults = results;
    return results;
  }

  const latencies = successResults.map(
    result => result.latencyMs
  );

  const validLatencies = validResults.map(
    result => result.latencyMs
  );

  console.log(
    "\n========== Read Latency Summary =========="
  );

  console.log(
    `Successful calls: ${successResults.length} / ${NUM_RUNS}`
  );

  console.log(
    `Valid pseudonym + 128-byte fingerprint records: ` +
    `${validResults.length} / ${NUM_RUNS}`
  );

  console.log(
    `Empty records: ` +
    `${successResults.filter(r => r.isEmpty).length}`
  );

  console.log(
    `Latency for all successful calls (ms): ` +
    `mean=${mean(latencies).toFixed(2)}, ` +
    `sample standard deviation=${sampleStdDev(latencies).toFixed(2)}, ` +
    `min=${Math.min(...latencies).toFixed(2)}, ` +
    `max=${Math.max(...latencies).toFixed(2)}, ` +
    `P50=${percentile(latencies, 0.50).toFixed(2)}, ` +
    `P95=${percentile(latencies, 0.95).toFixed(2)}`
  );

  if (validLatencies.length > 0) {
    console.log(
      `Valid-record latency (ms): ` +
      `mean=${mean(validLatencies).toFixed(2)}, ` +
      `sample standard deviation=` +
      `${sampleStdDev(validLatencies).toFixed(2)}`
    );
  }

  console.log(
    "\n💡 This result represents end-to-end client RPC retrieval latency."
  );

  console.log(
    "💡 A view call does not create an on-chain transaction, " +
    "and does not incur a gas fee payable by the user."
  );

                                     
  function escapeCsv(value) {
    const text =
      value === null || value === undefined
        ? ""
        : String(value);

    if (
      text.includes(",") ||
      text.includes('"') ||
      text.includes("\n")
    ) {
      return `"${text.replace(/"/g, '""')}"`;
    }

    return text;
  }

  const columns = [
    "run",
    "key",
    "returnedPseudonym",
    "latencyMs",
    "fingerprint",
    "fingerprintBytes",
    "timestamp",
    "isEmpty",
    "pseudonymMatches",
    "fingerprintLengthValid",
    "error"
  ];

  const csvRows = [
    columns.join(","),
    ...results.map(result =>
      columns
        .map(column => {
          let value = result[column];

          if (
            column === "latencyMs" &&
            typeof value === "number"
          ) {
            value = value.toFixed(2);
          }

          return escapeCsv(value);
        })
        .join(",")
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

  const url = URL.createObjectURL(blob);
  const downloadLink =
    document.createElement("a");

  downloadLink.href = url;
  downloadLink.download =
    "read_latency_results.csv";

  document.body.appendChild(downloadLink);
  downloadLink.click();
  downloadLink.remove();

  setTimeout(
    () => URL.revokeObjectURL(url),
    1000
  );

  console.log(
    "\n✅ CSV file download triggered: read_latency_results.csv"
  );

  window.__readTestResults = results;

  return results;
}

            
runReadLatencyTest(15);
