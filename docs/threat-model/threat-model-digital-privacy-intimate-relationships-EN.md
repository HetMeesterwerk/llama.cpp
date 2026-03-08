# Threat Model: Digital Privacy Risks in Intimate Relationships

**A Practical Guide for Understanding, Detecting, and Defending Against Digital Surveillance by Intimate Partners**

*Version 1.0 — March 2026*
*Focus region: The Netherlands / European Union*

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Threat Landscape Overview](#2-threat-landscape-overview)
3. [Attack Vector Taxonomy](#3-attack-vector-taxonomy)
4. [Risk Assessment Matrix](#4-risk-assessment-matrix)
5. [Detection Guide](#5-detection-guide)
6. [Defense & Mitigation Recommendations](#6-defense--mitigation-recommendations)
7. [Dutch Legal Framework](#7-dutch-legal-framework)
8. [Resources](#8-resources)
9. [References](#9-references)

---

## 1. Introduction

### 1.1 Purpose and Scope

This document is a **defensive threat model** that maps out how digital surveillance can occur within intimate relationships. Its purpose is to:

- Help individuals understand what digital surveillance threats exist
- Provide practical guidance for detecting if surveillance is occurring
- Offer actionable steps to protect personal privacy and digital safety
- Outline the legal framework in the Netherlands that protects individuals from unauthorized surveillance

This guide focuses specifically on **Intimate Partner Surveillance (IPS)** — the use of technology by a current or former romantic partner to monitor, track, or control another person without their informed and freely given consent.

### 1.2 Who This Guide Is For

- Individuals who suspect they may be subject to digital surveillance by a partner
- Domestic violence support workers and counselors
- Privacy advocates and digital rights organizations
- Researchers studying technology-enabled abuse
- Anyone who wants to understand and improve their digital privacy posture

### 1.3 Ethical Framing

Understanding threats is the first step toward protection. This guide deliberately focuses on **defense and detection** rather than providing a blueprint for surveillance. Knowledge of attack vectors empowers potential victims to recognize warning signs, take protective action, and seek appropriate help.

> **Important:** If you are in an abusive relationship and are concerned about your safety, removing surveillance tools or confronting your partner could escalate the situation. Please contact a professional support service first. In the Netherlands, call **Veilig Thuis: 0800-2000** (free, 24/7).

---

## 2. Threat Landscape Overview

### 2.1 What Is Intimate Partner Surveillance?

Intimate Partner Surveillance (IPS) encompasses any use of technology to monitor a partner's activities, communications, location, or behavior without their genuine, informed consent. It exists on a spectrum:

| Level | Description | Examples |
|-------|-------------|----------|
| **Casual snooping** | Opportunistic checking of an unlocked device | Reading messages when a phone is left unattended |
| **Account monitoring** | Leveraging shared or known credentials | Logging into a partner's email or social media |
| **Active tracking** | Using built-in or third-party tools for ongoing surveillance | Location sharing abuse, shared cloud photo monitoring |
| **Stalkerware** | Installing dedicated covert surveillance software | Apps designed to invisibly record all device activity |
| **Systematic control** | Comprehensive digital and physical monitoring | Combining multiple surveillance methods as part of coercive control |

### 2.2 Prevalence and Statistics

Digital surveillance in intimate relationships is more common than many people realize:

- **31,031** unique individuals worldwide were affected by stalkerware in 2023, a 5.8% increase from 2022 (Kaspersky, 2024)
- **2,645** stalkerware cases were detected in Europe in 2023, with the Netherlands consistently in the top 10 most-affected European countries
- **39%** of respondents in a 21-country survey (including the Netherlands) reported experiencing some form of violence or abuse from a current or former partner, including:
  - 16% received unwanted messages
  - 13% were filmed or photographed without consent
  - 10% had their location tracked without permission
  - 7% had stalkerware installed on their device without consent
- **38%** of people in 2024 found secret monitoring of a partner acceptable under certain circumstances — a sharp rise from 17% in 2021
- Only **37%** of people felt confident they knew what stalkerware was; less than 10% of those could identify all its surveillance capabilities

These numbers are likely significant underestimates, as stalkerware is designed to be undetectable and many victims are unaware they are being monitored.

### 2.3 The Stalkerware Ecosystem

Stalkerware refers to commercially available software that is marketed for "parental monitoring" or "employee tracking" but is widely used for intimate partner surveillance. These applications are installed on a target's device and typically operate covertly, with no visible icon or notification.

**Known stalkerware applications** (documented by security researchers and the Coalition Against Stalkerware):

| Application | Documented Capabilities |
|-------------|------------------------|
| **FlexiSpy** | Call recording, ambient recording, message interception, GPS tracking, camera access |
| **mSpy** | Message monitoring, GPS tracking, social media monitoring, keylogging |
| **TrackView** | Location tracking, remote camera/microphone activation (most prevalent globally in 2023 with 4,049 affected users) |
| **Cerberus** | Originally an anti-theft app; widely misused for covert tracking and remote device control |
| **iKeyMonitor** | Keystroke logging, screenshot capture, message monitoring |
| **Cocospy / Spyic** | GPS tracking, call/message monitoring, social media access |
| **TheTruthSpy** | (and variants: Copy9, MxSpy, iSpyoo, SecondClone, TheSpyApp, ExactSpy, FoneTracker, GuestSpy) — a family of apps with identical internal functionality under different branding |
| **Hoverwatch** | Call recording, SMS tracking, GPS location, camera snapshots |
| **pcTattletale** | Screen recording, keystroke logging (suffered a major data breach in 2024, exposing victim data) |

> **Note:** Many of these applications have suffered data breaches themselves, meaning that data collected from victims is subsequently exposed to third parties — compounding the harm. Using these applications puts both the target *and* the installer at risk.

---

## 3. Attack Vector Taxonomy

Each threat is assessed with a risk level (likelihood × impact), detection difficulty, and defensive mitigations.

### 3.A Physical Device Access

Physical access to a partner's device — even briefly — is the most common and most dangerous attack vector.

#### 3.A.1 Unlocked Device Snooping

| Attribute | Detail |
|-----------|--------|
| **Description** | Reading messages, photos, call logs, or browsing history on an unlocked or passcode-known device |
| **Prerequisites** | Physical access + known passcode or unlocked device |
| **Risk Level** | **HIGH** — Very common, low technical barrier |
| **Detection Difficulty** | **Very Hard** — Leaves minimal traces |
| **Detection Indicators** | Messages marked as read that you haven't read; notification badges cleared; apps left in different states than expected; device warm when it shouldn't be |
| **Mitigations** | Use biometric authentication (Face ID / fingerprint); enable auto-lock with short timeout (30 seconds); change passcode if compromised; enable App Lock features for sensitive apps |

#### 3.A.2 Installing Monitoring Software via Physical Access

| Attribute | Detail |
|-----------|--------|
| **Description** | Installing stalkerware or modifying device settings during a brief period of physical access |
| **Prerequisites** | Physical access (typically 5–15 minutes) + device passcode |
| **Risk Level** | **HIGH** — Enables comprehensive ongoing surveillance |
| **Detection Difficulty** | **Hard** — Designed to be invisible, but detectable with proper tools |
| **Detection Indicators** | Unusual battery drain; increased data usage; unknown apps in settings (not on home screen); device slower than expected; unknown device management profiles |
| **Mitigations** | Never leave devices unattended in accessible locations; use complex passcode rather than simple PIN; regularly audit installed apps and device profiles; keep OS updated (stalkerware often requires outdated OS) |

#### 3.A.3 Extracting Data from Old or Retired Devices

| Attribute | Detail |
|-----------|--------|
| **Description** | Accessing an old phone, tablet, or laptop that still contains personal data, logged-in accounts, or cached messages |
| **Prerequisites** | Physical access to the old device |
| **Risk Level** | **MEDIUM** — Data may be outdated but still sensitive; accounts may still be logged in |
| **Detection Difficulty** | **Very Hard** — Access to a device you no longer monitor is nearly undetectable |
| **Detection Indicators** | Check account activity logs for access from old device; review "active sessions" in messaging apps |
| **Mitigations** | **Always factory-reset old devices before storing or disposing of them**; sign out of all accounts on old devices; remove SIM cards; disable cloud sync |

#### 3.A.4 Shoulder Surfing / Passcode Observation

| Attribute | Detail |
|-----------|--------|
| **Description** | Observing passcode entry, reading messages over shoulder, or noting password inputs |
| **Prerequisites** | Proximity to the target during device use |
| **Risk Level** | **MEDIUM** — Enables all subsequent physical access attacks |
| **Detection Difficulty** | **Nearly Impossible** — Purely observational |
| **Detection Indicators** | Partner seems to know information they shouldn't; partner references content from private messages |
| **Mitigations** | Use biometrics as primary unlock method; shield screen when entering passcodes; change passwords if you suspect they have been observed; enable privacy screen protectors |

---

### 3.B Account-Level Access

Access to online accounts can provide extensive surveillance capability without requiring ongoing physical access to a device.

#### 3.B.1 Shared or Known Passwords

| Attribute | Detail |
|-----------|--------|
| **Description** | Using passwords shared during the relationship, guessed from personal knowledge, or obtained through shoulder surfing |
| **Prerequisites** | Knowledge of the password (often from earlier voluntary sharing) |
| **Risk Level** | **HIGH** — Common in relationships where credentials were once shared; provides full account access |
| **Detection Difficulty** | **Medium** — Detectable through account activity logs |
| **Detection Indicators** | Unknown login locations/times in account activity; "last active" timestamps on messaging apps that don't match your usage; emails marked as read that you haven't opened |
| **Mitigations** | Use unique passwords for every account; enable two-factor authentication (2FA); regularly review account activity and active sessions; change passwords if relationship dynamics change |

#### 3.B.2 Shared Apple ID / Google Account / Family Sharing

| Attribute | Detail |
|-----------|--------|
| **Description** | Leveraging shared ecosystem accounts that sync messages, photos, location, browsing history, and app usage across devices |
| **Prerequisites** | Shared account access (common in established relationships) |
| **Risk Level** | **VERY HIGH** — Provides comprehensive, real-time access to nearly all data |
| **Detection Difficulty** | **Hard** — Synced access appears as legitimate activity |
| **Detection Indicators** | Check which devices are linked to your Apple ID/Google account; review Family Sharing members; check iCloud/Google sync settings |
| **Mitigations** | **Use separate Apple IDs and Google accounts**; review and remove unknown devices from your account; disable syncing of sensitive data to shared accounts; set up a personal account even if a shared one exists |

#### 3.B.3 Recovery Email / Phone Number Control

| Attribute | Detail |
|-----------|--------|
| **Description** | If a partner's email or phone number is set as a recovery option, they can reset passwords and gain access to accounts |
| **Prerequisites** | Being listed as a recovery contact or controlling the recovery phone number |
| **Risk Level** | **HIGH** — Enables account takeover at any time |
| **Detection Difficulty** | **Medium** — Password reset notifications are sent, but may be intercepted |
| **Detection Indicators** | Unexpected password reset emails; being logged out of accounts unexpectedly; changes to account settings you didn't make |
| **Mitigations** | **Audit all recovery emails and phone numbers on every important account**; use a personal email and phone number that only you control; use authenticator apps instead of SMS-based 2FA |

#### 3.B.4 Session Hijacking via Logged-In Browsers

| Attribute | Detail |
|-----------|--------|
| **Description** | Accessing accounts that remain logged in on shared computers, tablets, or browsers |
| **Prerequisites** | Access to a shared or previously used device with saved sessions |
| **Risk Level** | **MEDIUM** — Limited to accounts with active sessions |
| **Detection Difficulty** | **Medium** — Detectable through active session reviews |
| **Detection Indicators** | Check "active sessions" or "logged in devices" in account settings; review browser saved passwords |
| **Mitigations** | Always log out on shared devices; use private/incognito browsing on shared computers; regularly review and revoke active sessions; use a password manager with auto-lock |

---

### 3.C Network-Level Surveillance

Monitoring network traffic and exploiting shared cloud services.

#### 3.C.1 Monitoring Home Network Traffic

| Attribute | Detail |
|-----------|--------|
| **Description** | Inspecting network traffic through router access, DNS logging, or network monitoring tools |
| **Prerequisites** | Admin access to the home router or network equipment |
| **Risk Level** | **MEDIUM** — Most traffic is encrypted (HTTPS), limiting visibility, but DNS queries and connection metadata are often visible |
| **Detection Difficulty** | **Hard** — Occurs at the network level, not on the device |
| **Detection Indicators** | Custom DNS settings on router; unfamiliar devices or software on the network; router admin password changed without your knowledge |
| **Mitigations** | Use a VPN on your devices; use DNS-over-HTTPS (DoH) or DNS-over-TLS; use mobile data for sensitive browsing; check router admin settings and change default passwords |

#### 3.C.2 Shared Cloud Storage and Synced Data

| Attribute | Detail |
|-----------|--------|
| **Description** | Accessing photos, documents, notes, or backups through shared cloud storage accounts (iCloud, Google Drive, Dropbox) |
| **Prerequisites** | Shared account or known credentials to cloud services |
| **Risk Level** | **HIGH** — Cloud storage often contains extensive personal data including automatic photo backups |
| **Detection Difficulty** | **Medium** — Access logs available on most platforms |
| **Detection Indicators** | Review sharing settings on cloud storage; check access logs; look for automatic backup settings you didn't configure |
| **Mitigations** | Use separate cloud accounts; disable automatic photo/document syncing to shared storage; review and revoke shared folder access; enable notifications for account logins |

#### 3.C.3 Location Sharing Services

| Attribute | Detail |
|-----------|--------|
| **Description** | Exploiting location-sharing features (Find My iPhone, Google Maps sharing, Find My Friends) that were voluntarily enabled and never revoked |
| **Prerequisites** | Previously enabled location sharing |
| **Risk Level** | **HIGH** — Provides real-time, continuous location tracking |
| **Detection Difficulty** | **Easy** — Visible in device settings, but often forgotten |
| **Detection Indicators** | Check Settings → Privacy → Location Services → Share My Location (iOS); check Google Maps → Location Sharing (Android); review Find My app for shared users |
| **Mitigations** | **Regularly audit location sharing settings**; revoke location sharing with people you no longer wish to share with; disable "Share My Location" entirely if not needed; review AirTag/SmartTag alerts for unknown trackers |

---

### 3.D Social Engineering & Behavioral

Non-technical methods that exploit trust and social dynamics.

#### 3.D.1 Manipulating a Partner into Sharing Access

| Attribute | Detail |
|-----------|--------|
| **Description** | Using emotional pressure, guilt, or false pretenses to obtain passwords, device access, or consent to monitoring |
| **Prerequisites** | Emotional influence over the target |
| **Risk Level** | **HIGH** — Bypasses all technical security measures |
| **Detection Difficulty** | **Very Hard** — Appears as voluntary sharing |
| **Detection Indicators** | Feeling pressured to share passwords "to prove trust"; being told monitoring is "normal" in relationships; partner becoming angry when you maintain digital boundaries |
| **Mitigations** | Recognize that healthy relationships do not require surrendering digital privacy; consult a counselor if you feel pressured; maintain personal passwords and boundaries |

#### 3.D.2 Using Children or Mutual Contacts for Information

| Attribute | Detail |
|-----------|--------|
| **Description** | Obtaining information about a partner's activities through children, family members, or mutual friends, either directly or by monitoring children's devices that are in contact with the target |
| **Prerequisites** | Shared social network or custody arrangements |
| **Risk Level** | **MEDIUM** — Provides indirect information gathering |
| **Detection Difficulty** | **Very Hard** — Conducted through social channels |
| **Detection Indicators** | Children or friends asking unusually specific questions about your activities; partner knowing information only shared with specific people |
| **Mitigations** | Be mindful of what information is shared with mutual contacts during sensitive periods; have age-appropriate conversations with children about privacy |

#### 3.D.3 Exploiting "Family Safety" Apps

| Attribute | Detail |
|-----------|--------|
| **Description** | Installing parental control or family safety apps (e.g., Life360, Google Family Link, Apple Screen Time) under the guise of family safety, then using their surveillance capabilities against a partner |
| **Prerequisites** | Social influence + ability to frame surveillance as "family safety" |
| **Risk Level** | **HIGH** — These apps are legitimate and thus harder to identify as threats; they may include location tracking, app monitoring, and screen time data |
| **Detection Difficulty** | **Medium** — Apps are visible but their surveillance scope may not be understood |
| **Detection Indicators** | Family safety apps installed that you didn't consent to or fully understand; being asked to install apps for "the family's safety"; partner having admin control over family safety settings |
| **Mitigations** | Understand the full capabilities of any family safety app before agreeing to install it; ensure mutual and equal access to settings; distinguish between child safety features and partner monitoring |

---

### 3.E Third-Party & AI-Enabled Threats

Advanced threats involving commercial products, artificial intelligence, and open-source intelligence.

#### 3.E.1 Commercial Stalkerware Applications

| Attribute | Detail |
|-----------|--------|
| **Description** | Purpose-built surveillance software installed on a target's device that can monitor virtually all device activity including messages, calls, GPS, camera, microphone, keystrokes, and social media |
| **Prerequisites** | Brief physical access to target device + device passcode |
| **Risk Level** | **VERY HIGH** — Comprehensive surveillance capability |
| **Detection Difficulty** | **Hard** — Designed to be invisible; may disable security software |
| **Detection Indicators** | See [Section 5: Detection Guide](#5-detection-guide) for detailed indicators |
| **Mitigations** | Keep OS updated; never jailbreak/root devices; use reputable mobile security software; regularly audit device profiles and installed apps |

#### 3.E.2 AI-Powered Behavioral Analysis (Emerging Threat)

| Attribute | Detail |
|-----------|--------|
| **Description** | Using AI/ML tools to analyze patterns in a partner's publicly available data, communication patterns, or behavioral metadata to infer activities |
| **Prerequisites** | Access to sufficient data (public social media, shared account data) |
| **Risk Level** | **LOW to MEDIUM** — Currently more theoretical than practical for individual use, but rapidly evolving |
| **Detection Difficulty** | **Very Hard** — Analysis can be done on already-collected data |
| **Detection Indicators** | Partner making accusations based on pattern analysis they couldn't have done manually; evidence of AI tool usage |
| **Mitigations** | Limit public social media exposure; review what metadata is shared; be aware this capability is emerging |

#### 3.E.3 Open Source Intelligence (OSINT) from Public Data

| Attribute | Detail |
|-----------|--------|
| **Description** | Gathering information from publicly available sources: social media posts, check-ins, tagged photos, public records, forum posts, review sites |
| **Prerequisites** | Internet access + knowledge of the target's online identities |
| **Risk Level** | **MEDIUM** — Surprisingly effective; many people underestimate how much they share publicly |
| **Detection Difficulty** | **Nearly Impossible** — Uses only public information |
| **Detection Indicators** | Partner references information you only shared publicly but not with them directly |
| **Mitigations** | Audit privacy settings on all social media; limit location tagging; review what is publicly visible on your profiles; Google yourself to see what is publicly available; be careful with check-ins and real-time location sharing on social media |

#### 3.E.4 Data Brokers and People-Search Sites

| Attribute | Detail |
|-----------|--------|
| **Description** | Using commercial data broker services or people-search websites to find personal information, addresses, phone numbers, and associated contacts |
| **Prerequisites** | Payment or free tier access to data broker sites |
| **Risk Level** | **LOW to MEDIUM** — Provides background information rather than real-time surveillance |
| **Detection Difficulty** | **Nearly Impossible** — Third-party access is not reported to the data subject (though GDPR gives EU residents rights here) |
| **Detection Indicators** | Partner knowing information they shouldn't (previous addresses, phone numbers, family connections) |
| **Mitigations** | Exercise your GDPR right to data deletion with data brokers; opt out of people-search sites; use the Dutch Data Protection Authority (Autoriteit Persoonsgegevens) to file complaints if necessary |

---

## 4. Risk Assessment Matrix

The following matrix summarizes the threats by likelihood (how commonly they occur in intimate partner contexts) and impact (the severity of the privacy violation):

| Threat | Likelihood | Impact | Overall Risk | Detection Difficulty |
|--------|-----------|--------|-------------|---------------------|
| Unlocked device snooping | Very High | Medium | **HIGH** | Very Hard |
| Shoulder surfing | High | Medium | **HIGH** | Nearly Impossible |
| Shared/known passwords | High | High | **VERY HIGH** | Medium |
| Shared Apple ID/Google account | High | Very High | **VERY HIGH** | Hard |
| Location sharing abuse | High | High | **VERY HIGH** | Easy |
| "Family safety" app abuse | Medium | High | **HIGH** | Medium |
| Installing stalkerware | Medium | Very High | **VERY HIGH** | Hard |
| Old device data extraction | Medium | Medium | **MEDIUM** | Very Hard |
| Recovery email/phone control | Medium | High | **HIGH** | Medium |
| Session hijacking (browsers) | Medium | Medium | **MEDIUM** | Medium |
| Cloud storage access | Medium | High | **HIGH** | Medium |
| Social engineering via contacts | Medium | Low | **MEDIUM** | Very Hard |
| OSINT from public data | Medium | Medium | **MEDIUM** | Nearly Impossible |
| Home network monitoring | Low | Medium | **LOW** | Hard |
| AI behavioral analysis | Low | Medium | **LOW** | Very Hard |
| Data broker information | Low | Low | **LOW** | Nearly Impossible |

**Key takeaway:** The most common and impactful threats are the simplest — shared passwords, shared accounts, location sharing abuse, and unlocked device snooping. Defending against these basic threats provides the most significant improvement to your privacy posture.

---

## 5. Detection Guide

### 5.1 Signs Your Device May Be Compromised

**Battery and Performance:**
- Unexplained battery drain (stalkerware runs continuously in the background)
- Device running warmer than usual
- Slower performance or increased lag
- Higher than expected mobile data usage

**Visual Indicators:**
- Unfamiliar apps in Settings → General → iPhone Storage (iOS) or Settings → Apps (Android)
- Unknown configuration profiles: Settings → General → VPN & Device Management (iOS)
- Unknown device administrators: Settings → Security → Device Admin Apps (Android)
- Camera or microphone indicator lights activating unexpectedly (green/orange dots on iOS)

**Account Anomalies:**
- Messages marked as read that you haven't opened
- "Last active" or "last seen" timestamps that don't match your usage
- Notification badges cleared on messaging apps
- Login notifications from unknown locations or times

### 5.2 How to Audit Your iOS Device

1. **Check installed apps:** Settings → General → iPhone Storage — review the full list of installed apps. Stalkerware may not appear on the home screen but will be visible here.
2. **Check device profiles:** Settings → General → VPN & Device Management. If this menu item exists and you see profiles you didn't install, investigate immediately.
3. **Check location sharing:** Settings → Privacy & Security → Location Services → Share My Location. Review who has access.
4. **Check linked devices:** Settings → [Your Name] → review all devices listed under your Apple ID.
5. **Check Find My:** Open Find My → People tab. Review who can see your location.
6. **Check Screen Time:** Settings → Screen Time. If this is enabled and you didn't set it up, someone may be monitoring your usage.
7. **Review account access:** Visit appleid.apple.com → Sign-In & Security → review trusted devices and recent activity.

### 5.3 How to Audit Your Android Device

1. **Check installed apps:** Settings → Apps → See All Apps (including system apps). Look for unfamiliar apps.
2. **Check device administrators:** Settings → Security → Device Admin Apps. Only your company MDM (if applicable) should be here.
3. **Check app permissions:** Settings → Privacy → Permission Manager. Review which apps have access to location, camera, microphone, and contacts.
4. **Check unknown sources:** Settings → Security → Unknown Sources. If enabled and you didn't do this, it may indicate sideloaded stalkerware.
5. **Check Google account:** Visit myaccount.google.com → Security → Your Devices and Recent Security Activity.
6. **Review location sharing:** Open Google Maps → your profile picture → Location Sharing.

### 5.4 How to Audit Your Accounts

For each important account (email, social media, banking, messaging):

1. **Review active sessions:** Most services show active/logged-in sessions. End any you don't recognize.
2. **Check login history:** Review recent login times, locations, and devices.
3. **Review recovery settings:** Ensure recovery email and phone number are yours and only yours.
4. **Check connected apps:** Review third-party apps that have been granted access to your account.
5. **Review forwarding rules:** In email accounts, check if mail forwarding has been set up to another address.

### 5.5 Physical Tracker Detection

- **AirTags / SmartTags:** iOS will alert you if an unknown AirTag is traveling with you. On Android, download the Apple "Tracker Detect" app or use "Unknown Tracker Alerts" (built into Android 14+).
- **GPS trackers:** Check vehicle for magnetic GPS trackers (common hiding spots: wheel wells, under bumpers, inside the trunk, attached to the undercarriage).
- **Bluetooth scanners:** Use a Bluetooth scanner app to detect unknown nearby devices that are always present.

---

## 6. Defense & Mitigation Recommendations

### 6.1 Device Hygiene

- [ ] Use biometric authentication (Face ID / fingerprint) as your primary unlock method
- [ ] Set a strong alphanumeric passcode (not a 4-digit PIN)
- [ ] Enable auto-lock with a short timeout (30 seconds to 1 minute)
- [ ] Keep your operating system updated to the latest version
- [ ] Do not jailbreak (iOS) or root (Android) your device
- [ ] Install a reputable mobile security app (Malwarebytes, Lookout, Kaspersky)
- [ ] Factory-reset old devices before storing, giving away, or selling them
- [ ] Enable lockdown mode (iOS) if you believe you are being targeted

### 6.2 Account Security

- [ ] Use a **unique, strong password** for every account (use a password manager)
- [ ] Enable **two-factor authentication** on all important accounts (prefer authenticator app over SMS)
- [ ] **Audit recovery settings** — ensure recovery email and phone number are exclusively yours
- [ ] Review and revoke access for **connected third-party apps**
- [ ] Check for **email forwarding rules** you didn't create
- [ ] **Review active sessions** monthly and end unfamiliar ones
- [ ] Use **separate accounts** from your partner for email, cloud storage, and device ecosystems

### 6.3 Network Privacy

- [ ] Use a **VPN** on your devices, especially on shared home networks
- [ ] Enable **DNS-over-HTTPS** (DoH) in your browser settings
- [ ] Use **mobile data** for sensitive browsing if you suspect network monitoring
- [ ] Change the **router admin password** from default and check DNS settings
- [ ] Consider a **separate network** (most routers support guest networks) for your personal devices

### 6.4 Social Media & Online Presence

- [ ] Audit **privacy settings** on all social media platforms
- [ ] Disable **location tagging** on posts and photos
- [ ] Review what is **publicly visible** on your profiles (view as external visitor)
- [ ] Be cautious with **real-time location sharing** (check-ins, stories with location)
- [ ] Google yourself to see what information is publicly available
- [ ] Limit what you share with **mutual contacts** during sensitive periods

### 6.5 Digital Safety Planning

If you are in an abusive situation, taking sudden action to remove surveillance tools or change passwords could alert an abusive partner and escalate danger. Instead:

1. **Contact a professional** before taking action (Veilig Thuis: 0800-2000)
2. **Use a safe device** — a device your partner does not have access to (a friend's phone, a public library computer, a new prepaid phone)
3. **Document evidence** — take screenshots or photos of surveillance tools before removing them, as this may be needed for legal proceedings
4. **Create a safety plan** — work with a domestic violence advocate to plan your steps
5. **Change credentials gradually** — if you do change passwords, do so as part of a coordinated safety plan, not impulsively
6. **Preserve evidence** — do not factory-reset a compromised device before professionals have had a chance to document the stalkerware, if you plan to pursue legal action

---

## 7. Dutch Legal Framework

### 7.1 Relevant Criminal Code Articles

Unauthorized digital surveillance of a partner is a criminal offense under Dutch law. The following articles of the Dutch Criminal Code (*Wetboek van Strafrecht*, Sr) are directly relevant:

#### Article 138ab Sr — Computer Trespass (*Computervredebreuk*)

Any person who **willfully and unlawfully accesses a computerized system** (or part thereof) is liable to imprisonment of up to **two years** or a fine of the fourth category (€23,750 as of 2025). This applies when access is obtained by:
- Breaching security measures
- Technical intervention
- Using false signals or a false key
- Assuming a false identity

**In context:** Accessing your partner's phone, email, or social media account without permission — even if you know the passcode — can constitute computer trespass if done without consent.

#### Article 139c Sr — Unlawful Interception of Communications (*Afluisteren*)

Willfully and unlawfully **intercepting or recording communications** not intended for you is punishable by imprisonment of up to **one year** or a fine of the fourth category.

**In context:** Intercepting a partner's WhatsApp messages, emails, or phone calls through surveillance software constitutes unlawful interception.

#### Article 139d Sr — Surveillance Devices (*Aftapapparatuur*)

Installing a **technical device** for the purpose of illegally eavesdropping, intercepting, or recording conversations, telecommunications, or data is a criminal offense. Manufacturing, obtaining, importing, distributing, or possessing tools primarily designed for such offenses carries a penalty of up to **two years** imprisonment.

**In context:** Installing stalkerware on a partner's device, or possessing tools designed for intercepting communications, violates this article.

#### Article 285b Sr — Stalking (*Belaging*)

Systematically **breaching another person's personal sphere** with the purpose of compelling them to act, refrain from acting, or to frighten them is punishable as stalking. Digital surveillance and monitoring can constitute stalking when it forms part of a systematic pattern.

**In context:** Ongoing digital surveillance of a partner — especially after a relationship has ended or when the partner has expressed they do not consent — may constitute stalking.

### 7.2 GDPR / AVG

The **General Data Protection Regulation** (in Dutch: *Algemene Verordening Gegevensbescherming*, AVG) provides additional protections:

- Processing personal data without a lawful basis is prohibited
- Individuals have the right to know what data is being collected about them
- The Dutch Data Protection Authority (*Autoriteit Persoonsgegevens*, AP) can investigate complaints and impose fines
- While the GDPR's "household exemption" excludes purely personal/domestic processing, this exemption does **not** apply to covert surveillance or stalkerware use

### 7.3 How to Report

1. **Contact the police (*Politie*):** File a report (*aangifte*) at your local police station or call 0900-8844 (non-emergency). For emergencies, call 112.
2. **Preserve digital evidence:** Take screenshots, document installed apps/profiles, note dates and times. Do not factory-reset a compromised device before consulting with police or a lawyer.
3. **Consult a lawyer:** A lawyer specializing in privacy law (*privacyrecht*) or criminal law (*strafrecht*) can advise on your specific situation. Legal aid (*gesubsidieerde rechtsbijstand*) is available through the Legal Aid Board (*Raad voor Rechtsbijstand*).
4. **File a complaint with the AP:** For GDPR violations, file a complaint at autoriteitpersoonsgegevens.nl.

### 7.4 Important Legal Notes

- **Knowing the passcode does not equal consent.** Even if passwords were shared during the relationship, using them to access a partner's accounts without current, informed consent can be illegal.
- **"Checking a phone" can be a crime.** There is a misconception that casually reading a partner's messages is harmless. Under Dutch law, it can constitute computer trespass (Art. 138ab).
- **Evidence obtained through surveillance may be inadmissible.** In Dutch civil proceedings (e.g., divorce), evidence obtained through illegal surveillance may be challenged, though courts have discretion.
- **Both parties can be liable.** If you use stalkerware, you may face criminal prosecution *and* the stalkerware company's data breach may expose your activities.

---

## 8. Resources

### 8.1 Dutch Support Organizations

| Organization | Contact | Description |
|-------------|---------|-------------|
| **Veilig Thuis** | 0800-2000 (free, 24/7) | Domestic violence and child abuse helpline |
| **Slachtofferhulp Nederland** | 0900-0101 | Victim support services |
| **Politie** | 0900-8844 (non-emergency) / 112 (emergency) | Dutch police |
| **Juridisch Loket** | 0900-8020 | Free legal advice |
| **Raad voor Rechtsbijstand** | rvr.org | Legal aid services |
| **Autoriteit Persoonsgegevens** | autoriteitpersoonsgegevens.nl | Dutch Data Protection Authority |
| **Blijf Groep** | 0800-2000 (via Veilig Thuis) | Shelters and support for domestic violence |

### 8.2 International Resources

| Organization | Website | Description |
|-------------|---------|-------------|
| **Coalition Against Stalkerware** | stopstalkerware.org | Multi-stakeholder initiative against stalkerware |
| **National Network to End Domestic Violence (NNEDV)** | nnedv.org | US-based; Safety Net project on tech and DV |
| **Citizen Lab** | citizenlab.ca | Academic research on surveillance technologies |
| **Electronic Frontier Foundation (EFF)** | eff.org | Digital rights and privacy advocacy |
| **AV-Comparatives** | av-comparatives.org | Independent security product testing (including stalkerware detection tests) |

### 8.3 Tools for Self-Assessment

- **Apple Safety Check (iOS 16+):** Settings → Privacy & Security → Safety Check — reviews and resets sharing and access permissions in one place
- **Google Security Checkup:** myaccount.google.com/security-checkup — reviews account security settings
- **Have I Been Pwned:** haveibeenpwned.com — check if your email/phone has been in data breaches
- **Tracker Detect (Android):** Apple's app to detect unknown AirTags
- **Kaspersky TinyCheck:** Open-source tool developed to detect stalkerware by analyzing network traffic (designed for use by domestic violence shelters)

---

## 9. References

1. Kaspersky (2024). *The State of Stalkerware 2023.* Securelist. https://securelist.com/state-of-stalkerware-2023/112135/
2. Coalition Against Stalkerware. *Understanding Technology-Enabled Abuse in Modern Relationships.* December 2024. https://stopstalkerware.org/2024/12/12/understanding-technology-enabled-abuse-in-modern-relationships/
3. AV-Comparatives & EFF (2025). *Stalkerware Test 2025.* https://www.av-comparatives.org/tests/stalkerware-test-2025/
4. European Institute for Gender Equality. *Netherlands — Stalking (Legal Definitions in the EU).* https://eige.europa.eu/gender-based-violence/regulatory-and-legal-framework/legal-definitions-in-the-eu/netherlands-stalking
5. Dutch Criminal Code (*Wetboek van Strafrecht*). Articles 138ab, 139c, 139d, 285b.
6. European Union. *General Data Protection Regulation (GDPR) / Algemene Verordening Gegevensbescherming (AVG).*
7. UNODC. *Article 139d — Netherlands Penal Code.* https://www.unodc.org/cld/en/legislation/nld/penal_code/second_book/article_139d/article_139d.html

---

*This document is provided for educational and defensive purposes. It is intended to help individuals protect their digital privacy and recognize potential surveillance. It should not be used to conduct surveillance against others. If you are experiencing domestic violence or abuse, please contact Veilig Thuis (0800-2000) or your local authorities.*
