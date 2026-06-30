# EUDI — START HERE (orientare pentru un agent care începe de la 0)

> **Scopul acestui document:** dacă ești un agent (sau om) care nu știe nimic despre programul EUDI al
> ROeID/Inspecția Muncii, **citește asta întâi**. Îți dă modelul mental, glosarul, harta repo-urilor și
> unde să cauți detaliile. Toate celelalte docuri sunt „deep dives" — aici e harta.

---

## 1. Ce este, în două fraze

Inspecția Muncii (IM) emite documente (întâi **extras salariat**) ca **credențiale digitale standard EUDI**
(SD-JWT VC) pe care **orice portofel EUDI conform** le poate importa și prezenta. Două piloni: **interoperabilitate**
(merge cu portofele/verificatori pe care NU i-am scris noi) și **conformitate cu standardul** (OpenID4VCI/VP, SD-JWT VC, eIDAS 2).

**Stare (2026-06):** bucla **emitere → import în portofel → prezentare → verificare** e **DOVEDITĂ end-to-end**
pe portofelul EUDI de referință (iOS), cu **sigiliul calificat real al IM**. Următoarea frontieră: **portofelul
propriu ROeID** (în `roeid_flutter`) + un **PID**.

---

## 2. Distribuția (repo-uri & servicii)

| Componentă | Rol | Stack | Stare |
|---|---|---|---|
| **reges-eudi** (`reges-wallet-issuer`) | **Issuer** OpenID4VCI al extras-salariat (SD-JWT VC, sigiliu IM) | NestJS | ✅ deployed dev |
| **reges-eudi-verifier** (`eudi-web-verifier`) | **Verifier** OpenID4VP (cod oficial EUDI + UI custom) | Kotlin/Spring | ✅ deployed |
| **reges-process** | **Orchestrator**: raport → arm-offer → QR în PDF → email tx_code | NestJS | ✅ issuance |
| **reges-sign** | Semnare PAdES (QES) + ștanțare QR + **sigiliul IM via STS** | .NET | ✅ |
| **pscid-api** | Backend ROeID: enrollment eID/NFC, conturi, `/enroll/eid/verify` (passive auth) | Node/Express | ✅ producție |
| **pscid-eudi** *(NOU, planificat)* | **PID issuer** (OpenID4VCI, `urn:eudi:pid:1`) — serviciu separat **în repo-ul pscid-api** | Node/Express | ⏳ plan |
| **roeid_flutter** *(NOU, planificat)* | **Portofelul ROeID** (hold + import + prezentare credențiale) | Flutter/Redux | ⏳ plan |
| **sdjwt_oid4vc** *(NOU, planificat)* | Librărie Dart de protocol SD-JWT VC + OID4VCI/VP (holder) | Dart pkg | ⏳ plan |
| **attested_secure_keys** | Librărie Dart: chei EC P-256 hardware + attestation (chei holder) | Dart pkg | ✅ pub.dev |

---

## 3. Concepte de bază (primer)

- **OpenID4VCI** = protocolul de **emitere** (issuer → portofel). Fluxul nostru: `credential_offer` (deep link
  `openid-credential-offer://`) → `POST /token` (grant `pre-authorized_code` + **`tx_code`**) → `POST /nonce`
  → `POST /credential` (întoarce credențiala). „Immediate issuance" (nu deferred).
- **OpenID4VP** = protocolul de **prezentare** (verifier → portofel). Verifierul publică o cerere (DCQL) ca QR;
  portofelul răspunde cu un `vp_token`.
- **SD-JWT VC** (`dc+sd-jwt`) = formatul credențialei: un JWT semnat de emitent + **disclosures** (câmpuri
  selectiv-dezvăluibile). La prezentare, portofelul atașează un **KB-JWT** (Key Binding) semnat cu cheia holder.
- **Selective disclosure** = dezvălui doar câmpurile cerute (ex. doar `employment_status`), nu tot.
- **vct** = tipul credențialei, URL rezolvabil (ex. `https://<issuer>/credentials/extras-salariat/v1`).
- **tx_code** = cod de activare one-time (canal separat: email) pe care userul îl introduce la import.

---

## 4. Modelul de încredere — TREI chei, NU le confunda (cea mai frecventă confuzie)

| Cheie / cert | Cine semnează | Ce semnează | Cine verifică | Listă de încredere |
|---|---|---|---|---|
| **(1) Sigiliul emitentului** | IM (reges-sign→STS) / ROeID (PID) | **atestatul** SD-JWT VC (`iss`, header `x5c`) | **verifierul** | LOTL / sigiliu calificat; dev = trust-all |
| **(2) Cert RP (RPAC)** | **verifierul** | **Request Object** OpenID4VP (JAR) | **portofelul** | `trustedReaderCertificates` (în app) |
| **(3) Cheia holder** | **portofelul** (pe device) | **KB-JWT** la prezentare (proof-of-possession) | **verifierul** (via `cnf`) | — (legată de credențială prin `cnf`) |

- „Could not trust certificate chain" în portofel = problemă pe **(2)** → rezolvat cu **RPAC** real din registrul EUDI.
- „UnsupportedVerificationMethod" în verifier = problemă pe **(1)** → rezolvat punând **`x5c`** în atestat.
- **(1) ≠ (2)**: sigiliul emitentului (verifierul îl crede) e ALT cert decât RPAC (portofelul îl crede). STS rezolvă (1), nu (2).
- **PID:** semnat tot pe planul (1), dar cu o **cheie de emitent ROeID separată** (≠ sigiliul IM, ≠ RPAC).

---

## 5. Bucla dovedită

```
reges-process (raport)  ──arm-offer──▶  reges-eudi (issuer, sigiliu IM, x5c, exp)
        │                                      │ OpenID4VCI (offer→token+tx_code→credential)
   reges-sign ștanțează QR în PDF              ▼
        │                              EUDI wallet (iOS referință)  ──present──▶  reges-eudi-verifier
   email tx_code ───────────────────▶                                                │ OpenID4VP (DCQL, KB-JWT)
                                                                          „Prezentare verificată" + claims + exp
```

---

## 6. Glosar (vocabularul domeniului)

| Termen | Sens |
|---|---|
| **PID** | Person Identification Data — credențialul fundamental de identitate (rulebook `urn:eudi:pid:1`). Emitent legitim = statul; ROeID îl **prototipează** pentru pilot. |
| **(Pub)EAA** | (Public-body) Electronic Attestation of Attributes — atestat de atribute (ex. extras_salariat = PuB-EAA al IM). |
| **holder key / `cnf`** | Cheia privată a portofelului, legată de credențială prin claim-ul `cnf`; semnează KB-JWT-ul. |
| **KB-JWT** | Key Binding JWT — semnătură proaspătă la prezentare peste `nonce` + `aud` + hash-ul prezentării. |
| **x5c** | Lanțul de cert al emitentului în header-ul SD-JWT (RFC 7515), cum verifierul rezolvă cheia emitentului. |
| **RPAC** | Relying Party Access Certificate — certul cu care **verifierul** se autentifică la **portofel**. |
| **arm-offer** | Endpoint-ul issuer-ului care creează o ofertă (`correlationId` + `offerUri` + `tx_code`). |
| **LOTL** | EU List of Trusted Lists (eIDAS) — sursa de încredere reală; producție, NU dev. |
| **WSCD** | Wallet Secure Cryptographic Device — hardware-ul certificat unde stau cheile (LoA High). |
| **WUA** | Wallet Unit Attestation — dovada că instanța de portofel e una genuină/certificată. |
| **key attestation** | Dovada că **cheia holder** trăiește în hardware (Android Keystore chain / iOS App Attest). |
| **correlationId / offerUri / tx_code** | vezi §3; `tx_code` nu se loghează niciodată în clar. |

---

## 7. Harta documentelor (unde caut detaliile)

| Vrei să înțelegi… | Citește |
|---|---|
| Statusul cross-repo, ce e gata vs deschis | `reges-wallet-issuer/docs/DEMO_STATUS.md` |
| Cum reluăm testarea local + jurnalul fix-urilor interop + trust model | `reges-wallet-issuer/CONTEXT.md` |
| Emiterea (Faza 0a) în detaliu | `reges-wallet-issuer/docs/FAZA_0A.md` |
| Prezentarea/verificarea (fluxul + erorile rezolvate) | `reges-wallet-issuer/docs/FAZA_0_PREZENTARE.md` |
| Idei viitoare (cross-employer, PDF legat de atestat) | `reges-wallet-issuer/docs/FAZA_1_IDEI.md` |
| Designul complet (RO, prezentabil) | `pscid-api/EUDI_WALLET_POC_RO.md` |
| **Planul portofelului propriu + PID** | `roeid_flutter/docs/EUDI_WALLET_PLAN.md` |
| **Librăria de protocol Dart** | `roeid_flutter/docs/SDJWT_OID4VC_LIB.md` (se mută în repo-ul `sdjwt_oid4vc`) |

---

## 8. Onestitate (pilot vs producție) — citește înainte de a promite ceva

- Verifierul nostru e **trust-all** în dev (fără Trusted List) → acceptă orice emitent cu `x5c`. Pentru
  verificatori **terți** ai nevoie de **LOTL** (governance, nu cod).
- Un **PID emis de ROeID** e „real" **doar în ecosistemul nostru** până la desemnare/LOTL. Pentru terți = artefact de pilot.
- RPAC-ul e **artefact de test** (CA „PID Issuer CA 02" EU, non-producție). Producție = RPAC `C=RO` de la Access CA național.
- **STS TSA** (`ca.stsisp.ro:1111`) **geo-blochează** clusterul de dev (Germania) → dev folosește DigiCert TSA; **prod = STS**.
