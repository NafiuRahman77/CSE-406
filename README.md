# CSE 406 Computer Security Sessional

This repository contains assignments and projects for the **CSE 406 Computer Security Sessional** course. Each task focuses on practical implementations of security concepts, ranging from cryptographic algorithms to attack simulations.

---

## Assignments

### Offline-1: AES and ECC Implementation
- **Description:**
  - Implemented AES (Advanced Encryption Standard) in `aes.py`.
  - Implemented ECC (Elliptic Curve Cryptography) in `elliptic_curve_diffie_hellman.py`.
  - Simulated secure communication using the `client.py` and `server.py` scripts, where:
    - `client.py` acts as Bob.
    - `server.py` acts as Alice.
  - Encryption and decryption were handled using a combination of AES and ECC.

### Offline-2: XSS Attack
- **Description:**
  - Implemented a Cross-Site Scripting (XSS) attack using JavaScript.
  - Targeted the **Elgg** platform with an intruder named "Samy."
  - Demonstrated how malicious JavaScript can be injected to exploit vulnerabilities in the website.
  - Details can be found in the **report** of Offline-2 folder.

### Online-1: Buffer Overflow Attack
- **Description:**
  - Developed a buffer overflow attack to exploit a vulnerable C program.
  - Utilized `gdb` to identify the attack address and `exploit.py` to write malicious content to that specific address.

---

## Project: Mobile Security Framework (MobSF)
- **Description:**
  - Provided a detailed analysis of the **Mobile Security Framework (MobSF)** tool.
  - Explored its functionality and explained its codebase.
  - Highlighted its utility for static and dynamic analysis of mobile applications.


---

## How to Run

### Offline-1: AES and ECC
1. Navigate to the `Offline-1` directory:
   ```bash
   cd Offline-1
   ```
2. Run the `server.py` (Alice) and `client.py` (Bob) in separate terminals:
   ```bash
   python server.py
   python client.py
   ```

### Offline-2: XSS Attack
1. Inject the `task1/2/3/4.html` file in the profile description of the browser **Seed Lab** to observe the XSS attack.
2. Ensure the Elgg platform is set up to simulate the attack.

### Online-1: Buffer Overflow Attack
1. Compile the `vulnerable_code.c`:
   ```bash
   gcc -o vulnerable vulnerable_code.c -fno-stack-protector -z execstack
   ```
2. Run `exploit.py` to create the malicious payload:
   ```bash
   python exploit.py
   ```
3. Execute the `vulnerable` program with the crafted payload.

---

## Contact
For questions or collaboration, please reach out via email or GitHub.

- **Email:** nafiu.rahman@gmail.com
- **GitHub:** [NafiuRahman77](https://github.com/NafiuRahman77)
