<br />
<div align="center">
  <a href="https://github.com/cryxnet/subvance">
    <img src="assets/subvance.png" alt="Logo" width="100" height="50">
  </a>

  <h3 align="center">Subvance</h3>

  <p align="center">
Subvance is a advance subdomain discovery tool that can actively or passively discover
subdomains of a domain. It uses techniques like brute-forcing, google dorks, certificate fingerprinting,
and querying databases to generate a list of potential subdomains.
The tool is efficient and can help improve overall security.
    <br />
    <a href="https://github.com/cryxnet/subvance"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/cryxnet/subvance/issues">Report Bug</a>
    ·
    <a href="https://github.com/cryxnet/subvance/issues">Request Feature</a>
  </p>
</div>

## Installation

To install the project and its dependencies, follow these steps:

1. Clone the repository to your local machine:

```bash
git clone https://github.com/cryxnet/subvance.git
```

2. Navigate to the project directory:

```bash
cd subvance
```

3. Create a virtual environment for the project:

```bash
python -m venv venv
```

4. Activate the virtual environment:

**On Windows:**

```bash
venv\Scripts\activate
```

**On macOS or Linux:**

```bash
source venv/bin/activate
```

5. Install the project dependencies:

```bash
pip install -r requirements.txt
```

6. Execute subvance.py with the arguments (look [usage](#usage))

```bash
python subvance.py <args>
```

## Usage

```bash
subvance.py [-h] [-o OUTPUT_FILE_PATH] [--cert-fingerprint] [--brute-force] [--google-dorks] [--passive] [--active]
            [--all] [--wordlist WORDLIST_PATH]
            domain
```

## Techniques

### Active Techniques

#### Bruteforcing

- Brute force guessing of subdomains by trying out common or random strings in the domain name

### Passive Techniques

#### Certificate Fingerprinting

- Extracting subdomains from SSL/TLS certificates of a domain or its subdomains
- Has data use we use the `crt.sh` database.
- **Information:** Currently the crt.sh database is not available 100%. If it doesn't work it will display it in the logs: `ERROR - Failed certificate fingerprinting for domain: example.com with status code: 502 (or others)`

#### Google Dorks

- With the power of google dorks, we collect indexed sudomains.

## Roadmap

- [x] Bruteforcing (active discovery)
- [x] Google dorks discovery (passive discovery)
- [x] Certificate Fingerprinting (passive discovery)
- [ ] History of DNS Recrods (passive discovery)
- [ ] looking for new techniques (active and passiv discovery)

## Disclaimer

```nothing
YOUR USAGE OF THIS PROJECT CONSTITUTES YOUR AGREEMENT TO THE FOLLOWING TERMS:

    THE MISUSE OF THE DATA PROVIDED BY THIS PROJECT AND ITS MALWARES MAY LEAD TO CRIMINAL CHARGES AGAINST THE PERSONS CONCERNED.

    I DO NOT TAKE ANY RESPONSIBILITY FOR THE CASE. USE THIS PROJECT ONLY FOR RESEARCH PURPOSES, EDUCATIONAL PURPOSES & ETHICAL ONLY.

    Subvance is a project related to Computer Security and for Educational Purposes and not a project that promotes illegal activities.

    Don't use this Project for any illegal activities.

    If something happens, we do not take any liability.

    Subvance should be considered as a project for educational purposes.
```

## Author

Created by [cryxnet](https://cryxnet.com/)

If you find this project helpful, please give it a ⭐️ on GitHub to show your support.
I would also appreciate it if you shared it with others who might find it useful!
