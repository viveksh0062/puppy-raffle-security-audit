# 🐶 Puppy Raffle – Smart Contract Security Audit

This repository documents my **first independent smart contract security audit**, conducted on the **PuppyRaffle** protocol.

The goal of this audit was to identify **security vulnerabilities, logic flaws, and denial-of-service risks** that could impact user funds, fairness of the raffle, or protocol availability.

---

## 📌 Audit Overview

- **Target Contract:** PuppyRaffle
- **Audit Type:** Manual review + Foundry-based testing
- **Focus Areas:**
  - Denial of Service (DoS)
  - Reentrancy
  - Weak Randomness
  - Accounting & Overflow
  - General Solidity best practices

This audit was performed **without access to privileged information** and assumes a **hostile on-chain environment**.

---

## 🧾 Findings Summary

| Severity  | Count          |
| --------- | -------------- |
| 🔴 High    | 3              |
| 🟡 Medium  | 1              |
| 🟢 Low     | 1              |
| **Total** | **5 Findings** |

---

## 🚨 High Severity Findings (3)

- **Denial of Service via unbounded nested loops**  
  A quadratic duplicate-check loop causes gas costs to scale with the square of the number of players, eventually making `enterRaffle` unusable.

- **Accounting overflow in `totalFees` leading to permanent DoS**  
  `totalFees` was stored as a `uint64`, causing arithmetic overflow after sufficient raffles and permanently reverting `selectWinner`.

- **Reentrancy risk due to external ETH transfer before full state finalization**  
  Prize distribution uses low-level calls that can be abused by malicious contracts to re-enter execution paths.

---

## ⚠️ Medium Severity Finding (1)

- **Weak on-chain randomness for winner and rarity selection**  
  The protocol relies on predictable on-chain values (`block.timestamp`, `block.difficulty / prevrandao`, `msg.sender`) to generate randomness, allowing attackers to influence outcomes.

---

## ℹ️ Low Severity Finding (1)

- **Gas inefficiencies and minor logic inconsistencies**  
  Includes suboptimal patterns that do not directly compromise security but increase costs or reduce clarity.

---

## 🧪 Testing & Proof of Concepts

All high-impact issues were validated using **Foundry tests**, including:
- Gas comparison tests demonstrating DoS conditions
- Overflow reproduction tests
- Adversarial execution paths

PoCs are included inside the `test/` directory and individual finding files.

---

## 🧠 Key Takeaways

- Even seemingly harmless design decisions (like duplicate checks or storage packing) can introduce **critical vulnerabilities**.
- Gas-based DoS and accounting overflows are **easy to miss but highly destructive**.
- Proper audit mindset requires assuming **malicious users, contracts, and block producers**.

This audit was a major learning milestone and helped solidify my understanding of **real-world smart contract attack surfaces**.

---

## 👤 About Me

This was my **first complete smart contract audit**, conducted as part of my journey into **Web3 security research**.

- 🐦 X (Twitter): https://x.com/viveksh0062 
- 🧵 LinkedIn : https://www.linkedin.com/in/vivek-sharma-679606360/  

I am actively learning, practicing audits, and writing PoCs using **Foundry**.

---

## ⚠️ Disclaimer

This audit does not guarantee the absence of vulnerabilities.  
The findings represent a **best-effort security review** based on the time and scope available.

---

⭐ If you find this audit useful, feel free to explore the findings or reach out for feedback.
# Puppy-Raffle-Audit
