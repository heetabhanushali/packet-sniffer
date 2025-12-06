"""
Legal Compliance Module

Displays legal notices and obtains user consent before packet capture.
Ensures compliance with wiretap laws in USA, UK, and India.
"""

import sys
from datetime import datetime
from typing import Optional


# =============================================================================
# Legal Notice Text
# =============================================================================

LEGAL_NOTICE = """
╔══════════════════════════════════════════════════════════════════════════╗
║                          LEGAL NOTICE                                    ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  This tool captures and analyzes network traffic.                       ║
║                                                                          ║
║  ✓ LEGAL USES:                                                          ║
║    • Monitoring YOUR OWN computer's network activity                    ║
║    • Analyzing networks YOU OWN or have written permission to monitor   ║
║    • Educational purposes on authorized networks                        ║
║    • Security auditing with proper authorization                        ║
║    • Network troubleshooting on your own infrastructure                 ║
║                                                                          ║
║  ✗ ILLEGAL USES:                                                        ║
║    • Intercepting communications without authorization                  ║
║    • Monitoring networks you do not own or control                      ║
║    • Capturing traffic on public/corporate WiFi without permission      ║
║    • Any form of unauthorized surveillance or wiretapping               ║
║    • Accessing others' private communications                           ║
║                                                                          ║
║  ⚖️  LEGAL COMPLIANCE (USA):                                             ║
║    • Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030             ║
║      Prohibits unauthorized access to computer systems                  ║
║                                                                          ║
║    • Wiretap Act, 18 U.S.C. § 2511                                      ║
║      Prohibits intentional interception of electronic communications    ║
║                                                                          ║
║    • Electronic Communications Privacy Act (ECPA)                       ║
║      Protects wire, oral, and electronic communications                 ║
║                                                                          ║
║    • Stored Communications Act (SCA), 18 U.S.C. § 2701                  ║
║      Protects stored electronic communications                          ║
║                                                                          ║
║    Penalties: Up to 5 years imprisonment and/or fines up to $250,000   ║
║                                                                          ║
║  ⚖️  LEGAL COMPLIANCE (UK):                                              ║
║    • Computer Misuse Act 1990                                           ║
║      Section 1: Unauthorized access to computer material                ║
║      Section 2: Unauthorized access with intent                         ║
║      Section 3: Unauthorized modification of computer material          ║
║                                                                          ║
║    • Regulation of Investigatory Powers Act 2000 (RIPA)                 ║
║      Regulates interception of communications                           ║
║                                                                          ║
║    • Data Protection Act 2018 / UK GDPR                                 ║
║      Protects personal data and privacy                                 ║
║                                                                          ║
║    • Investigatory Powers Act 2016                                      ║
║      Regulates use of investigatory powers by public bodies             ║
║                                                                          ║
║    Penalties: Up to 2 years imprisonment and unlimited fines           ║
║                                                                          ║
║  ⚖️  LEGAL COMPLIANCE (INDIA):                                           ║
║    • Information Technology Act, 2000 (IT Act)                          ║
║      Section 43: Unauthorized access to computer systems                ║
║      Section 66: Computer related offences                              ║
║      Section 66B: Dishonestly receiving stolen computer resource        ║
║      Section 66C: Identity theft                                        ║
║      Section 66D: Cheating by personation using computer resource       ║
║      Section 66E: Violation of privacy                                  ║
║      Section 66F: Cyber terrorism                                       ║
║                                                                          ║
║    • Indian Penal Code (IPC)                                            ║
║      Section 354C: Voyeurism                                            ║
║      Section 378: Theft                                                 ║
║      Section 420: Cheating                                              ║
║      Section 463: Forgery                                               ║
║                                                                          ║
║    • Telegraph Act, 1885                                                ║
║      Section 5(2): Interception of messages                             ║
║                                                                          ║
║    • Indian Evidence Act, 1872                                          ║
║      Section 65B: Admissibility of electronic records                   ║
║                                                                          ║
║    Penalties: Up to 3 years imprisonment and/or fines up to ₹5 lakh   ║
║               (Cyber terrorism: Life imprisonment)                      ║
║                                                                          ║
║  🔒 PRIVACY & SECURITY:                                                  ║
║    • Only metadata is captured (source, destination, protocol, size)    ║
║    • No decryption of encrypted traffic (HTTPS/TLS/SSL)                 ║
║    • No password interception or credential harvesting                  ║
║    • No content inspection of encrypted communications                  ║
║    • Data stays local (127.0.0.1) when web integration is enabled       ║
║    • No third-party data transmission or cloud storage                  ║
║    • Promiscuous mode disabled by default (only YOUR traffic)           ║
║                                                                          ║
║  ⚠️  DISCLAIMER:                                                         ║
║    The developer and contributors are NOT responsible for:              ║
║    • Any misuse of this tool                                            ║
║    • Any legal consequences arising from unauthorized use               ║
║    • Any damage caused by use of this software                          ║
║    • Compliance with laws in your specific jurisdiction                 ║
║                                                                          ║
║    This tool is provided "AS IS" without warranty of any kind.          ║
║                                                                          ║
║    By using this software, you acknowledge that:                        ║
║    1. You have read and understood this legal notice                    ║
║    2. You will use this tool only for legal and ethical purposes        ║
║    3. You are solely responsible for compliance with applicable laws    ║
║    4. You will obtain proper authorization before monitoring networks   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

SHORT_NOTICE = """
╔══════════════════════════════════════════════════════════════════════════╗
║  ⚠️  LEGAL NOTICE: Network Traffic Capture Tool                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  This tool captures network traffic and is subject to laws in:          ║
║                                                                          ║
║  🇺🇸 USA:   CFAA, Wiretap Act, ECPA                                     ║
║  🇬🇧 UK:    Computer Misuse Act 1990, RIPA, Data Protection Act         ║
║  🇮🇳 INDIA: IT Act 2000, IPC, Telegraph Act 1885                         ║
║                                                                          ║
║  ✅ ONLY use on:                                                         ║
║     • Your own computer/network                                         ║
║     • Networks with written authorization                               ║
║                                                                          ║
║  ❌ ILLEGAL to use on:                                                   ║
║     • Public WiFi, corporate networks, school networks                  ║
║     • Any network without explicit permission                           ║
║                                                                          ║
║  ⚖️  Unauthorized use may result in criminal prosecution                ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

CONSENT_PROMPT = """
╔══════════════════════════════════════════════════════════════════════════╗
║                        LEGAL CONSENT REQUIRED                            ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  By typing 'yes', you confirm that:                                     ║
║                                                                          ║
║  ✓ You have read and understood the legal notice above                  ║
║  ✓ You will only use this tool on networks you own or are authorized    ║
║    to monitor                                                            ║
║  ✓ You understand the legal consequences of unauthorized interception   ║
║  ✓ You accept full legal responsibility for your use of this tool       ║
║  ✓ You will comply with all applicable laws in your jurisdiction        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

Do you understand and agree to these terms? (yes/no): """


# =============================================================================
# Legal Compliance Functions
# =============================================================================

def show_legal_notice(full: bool = True):
    """
    Display legal notice.
    
    Args:
        full: If True, show full notice. If False, show short version.
    """
    if full:
        print(LEGAL_NOTICE)
    else:
        print(SHORT_NOTICE)


def get_user_consent(skip_prompt: bool = False) -> bool:
    """
    Get explicit user consent to proceed.
    
    Args:
        skip_prompt: If True, skip the interactive prompt (for automated use).
    
    Returns:
        True if user consents, False otherwise.
    """
    if skip_prompt:
        return True
    
    try:
        response = input(CONSENT_PROMPT).strip().lower()
        
        if response in ['yes', 'y']:
            print("\n✓ Legal consent granted")
            print("  Session will be logged with timestamp and interface")
            return True
        else:
            print("\n✗ Legal consent denied")
            print("  You must agree to the legal terms to use this tool.")
            return False
            
    except (KeyboardInterrupt, EOFError):
        print("\n\n✗ Aborted by user.")
        return False


def check_legal_compliance(
    show_full_notice: bool = True,
    require_consent: bool = True
) -> bool:
    """
    Complete legal compliance check.
    
    Args:
        show_full_notice: Whether to show full legal notice.
        require_consent: Whether to require user consent.
    
    Returns:
        True if user agrees to legal terms, False otherwise.
    
    Example:
        >>> if not check_legal_compliance():
        ...     sys.exit(1)
    """
    # Show notice
    show_legal_notice(full=show_full_notice)
    
    # Get consent
    if require_consent:
        if not get_user_consent():
            return False
    
    return True


def log_session_start(interface: str, log_file: Optional[str] = None):
    """
    Log the start of a capture session.
    
    Args:
        interface: Network interface being monitored.
        log_file: Optional log file path. If None, just prints.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"\n{'='*70}\n"
        f"  SESSION START LOG\n"
        f"{'='*70}\n"
        f"  Timestamp: {timestamp}\n"
        f"  Interface: {interface}\n"
        f"  Legal Consent: YES (user accepted terms)\n"
        f"  Compliance: USA (CFAA, ECPA), UK (CMA 1990), India (IT Act 2000)\n"
        f"{'='*70}\n"
    )
    
    if log_file:
        try:
            with open(log_file, 'a') as f:
                f.write(log_entry + "\n")
        except Exception:
            pass  # Silent fail for logging
    
    # Always print to console
    print(log_entry)


def show_jurisdiction_info(country_code: str = "ALL"):
    """
    Show specific jurisdiction information.
    
    Args:
        country_code: 'USA', 'UK', 'INDIA', or 'ALL'
    """
    jurisdictions = {
        'USA': """
╔══════════════════════════════════════════════════════════════════════════╗
║  🇺🇸 UNITED STATES LEGAL FRAMEWORK                                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030                ║
║  • Prohibits unauthorized access to protected computers                 ║
║  • Penalties: Up to 10 years for repeat offenders                       ║
║                                                                          ║
║  Wiretap Act - 18 U.S.C. § 2511                                         ║
║  • Criminalizes intentional interception of electronic communications   ║
║  • Requires consent of at least one party (varies by state)             ║
║  • Penalties: Up to 5 years imprisonment, $250,000 fine                 ║
║                                                                          ║
║  Electronic Communications Privacy Act (ECPA)                           ║
║  • Extends wiretap protections to electronic communications             ║
║  • Covers emails, stored communications, real-time interception         ║
║                                                                          ║
║  State Laws:                                                            ║
║  • Two-party consent states: CA, CT, FL, IL, MD, MA, MT, NH, PA, WA    ║
║  • One-party consent: Most other states                                 ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
""",
        'UK': """
╔══════════════════════════════════════════════════════════════════════════╗
║  🇬🇧 UNITED KINGDOM LEGAL FRAMEWORK                                      ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Computer Misuse Act 1990                                               ║
║  • Section 1: Unauthorized access (up to 2 years)                       ║
║  • Section 2: Unauthorized access with intent (up to 5 years)           ║
║  • Section 3: Unauthorized modification (up to 10 years)                ║
║                                                                          ║
║  Regulation of Investigatory Powers Act 2000 (RIPA)                     ║
║  • Part 1, Chapter 1: Interception of communications                    ║
║  • Requires authorization for lawful interception                       ║
║  • Penalties: Up to 2 years imprisonment                                ║
║                                                                          ║
║  Data Protection Act 2018 / UK GDPR                                     ║
║  • Protects personal data and privacy rights                            ║
║  • Requires lawful basis for processing                                 ║
║  • Penalties: Up to £17.5 million or 4% of turnover                     ║
║                                                                          ║
║  Investigatory Powers Act 2016 ("Snoopers' Charter")                    ║
║  • Regulates interception and surveillance powers                       ║
║  • Requires warrants for lawful interception                            ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
""",
        'INDIA': """
╔══════════════════════════════════════════════════════════════════════════╗
║  🇮🇳 INDIA LEGAL FRAMEWORK                                               ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Information Technology Act, 2000 (IT Act)                              ║
║  • Section 43: Unauthorized access - Compensation up to ₹1 crore       ║
║  • Section 66: Computer related offences - Up to 3 years, ₹5 lakh      ║
║  • Section 66B: Receiving stolen computer resource - 3 years, fine     ║
║  • Section 66C: Identity theft - 3 years, ₹1 lakh                      ║
║  • Section 66D: Cheating by personation - 3 years, ₹1 lakh            ║
║  • Section 66E: Violation of privacy - 3 years, ₹2 lakh               ║
║  • Section 66F: Cyber terrorism - Life imprisonment                     ║
║                                                                          ║
║  Indian Penal Code (IPC)                                                ║
║  • Section 354C: Voyeurism - Up to 3 years, fine                       ║
║  • Section 378: Theft - Up to 3 years, fine                            ║
║  • Section 420: Cheating - Up to 7 years, fine                         ║
║  • Section 463-465: Forgery - Up to 2 years, fine                      ║
║                                                                          ║
║  Telegraph Act, 1885                                                    ║
║  • Section 5(2): Unauthorized interception of messages                  ║
║  • Penalties: Up to 3 years imprisonment                                ║
║                                                                          ║
║  Digital Personal Data Protection Act, 2023                             ║
║  • Protects personal data of individuals                                ║
║  • Penalties: Up to ₹250 crore for violations                          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    }
    
    if country_code == "ALL":
        for info in jurisdictions.values():
            print(info)
    elif country_code in jurisdictions:
        print(jurisdictions[country_code])


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("LEGAL COMPLIANCE MODULE TEST")
    print("=" * 80)
    
    # Test full notice
    print("\n--- Testing Full Legal Notice ---")
    show_legal_notice(full=True)
    
    # Test consent
    print("\n--- Testing User Consent ---")
    if check_legal_compliance(show_full_notice=False, require_consent=True):
        print("\n✓ User consented")
        log_session_start("test0")
    else:
        print("\n✗ User did not consent")
    
    # Test jurisdiction info
    print("\n--- Testing Jurisdiction Info ---")
    print("\n[1] USA Specific:")
    show_jurisdiction_info("USA")
    
    print("\n[2] UK Specific:")
    show_jurisdiction_info("UK")
    
    print("\n[3] India Specific:")
    show_jurisdiction_info("INDIA")
    
    print("\n" + "=" * 80)
    print("Test complete.")
    print("=" * 80)