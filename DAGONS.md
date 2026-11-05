# Dragon Integration for wifit3

This branch integrates the 4 Dragon tools for enhanced WPA3-SAE attacks:

## Components

### 1. dragonforce (SAE Brute-Force)
- **Location:** `src/wifit3/crack/dragonforce.py`
- **Purpose:** CPU-based WPA3-SAE password cracking
- **Features:**
  - Brainpool P-256 curve support (SAE group 19)
  - Pure Python implementation
  - SHA-256 PRF for pwd-value computation
  - Optimized password verification

### 2. dragonslayer (SAE Vulnerability Attacks)
- **Location:** `src/wifit3/campaigns/dragonslayer.py`
- **Purpose:** Exploit WPA3-SAE implementation vulnerabilities
- **Attacks:**
  - Reflection attack (-a 0)
  - Invalid curve attack (-a 1, -a 2)
  - Zero-scalar attack (-a 3)

### 3. dragonblood (Reference)
- **Location:** `dragonblood/` (static files)
- **Purpose:** WPA3 Dragonfly analysis reference
- **Usage:** Documentation and research

### 4. dragondrain-and-time (Aircrack-ng)
- **Location:** `dragondrain-and-time/` (source)
- **Purpose:** WEP/WPA cracking suite
- **Integration:** External tool fallback

## Usage

### SAE Cracking (dragonforce)
```python
from wifit3.crack import dragonforce_crack_sae

password = dragonforce_crack_sae(
    ap_addr=ap_mac,
    client_addr=client_mac,
    ap_element=ap_sae_element,
    client_element=client_sae_element,
    ap_confirm=ap_confirm,
    client_confirm=client_confirm,
    passwords=password_list
)
```

### Dragonslayer Campaign
```python
from wifit3.campaigns.dragonslayer import DragonslayerCampaign, DragonslayerAttack

campaign = DragonslayerCampaign(
    interface=iface,
    bssid=ap_bssid,
    ssid=network_ssid,
    attack_type=DragonslayerAttack.REFLECTION,
    channel=36
)

result = await campaign.run()
```

## Minimal Integration Points

1. **Vault Integration:** Add SAE hashlines to vault alongside WPA handshakes
2. **UI Integration:** Add "Crack SAE" button in focus screen for WPA3 networks
3. **Auto-Crack:** Trigger dragonforce when SAE capture completes

## TODO

- [ ] Full EC operations for SAE verification
- [ ] Dragonslayer wpa_supplicant integration
- [ ] UI buttons for SAE cracking
- [ ] Vault SAE hashline format
- [ ] Tests for dragonforce module
