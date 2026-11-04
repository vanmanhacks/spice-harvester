FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq gawk git curl wget unzip golang-go rsync \
    ripgrep openssh-client gnupg python3 python3-pip \
    nmap whatweb dnsutils whois dnsmasq proxychains4 \
    && rm -rf /var/lib/apt/lists/*

# DNS caching resolver — fixes CT log DNS timeouts over VPN
# All container tools resolve via 127.0.0.1:53 → dnsmasq cache → upstream
RUN echo "no-resolv" >> /etc/dnsmasq.conf && \
    echo "server=1.1.1.1" >> /etc/dnsmasq.conf && \
    echo "server=8.8.8.8" >> /etc/dnsmasq.conf && \
    echo "cache-size=1000" >> /etc/dnsmasq.conf && \
    echo "listen-address=127.0.0.1" >> /etc/dnsmasq.conf && \
    echo "bind-interfaces" >> /etc/dnsmasq.conf

# Go tools — ProjectDiscovery + tomnomnom + Hakluke + g0lden
# === ACTIVE (used by weekly-light.sh / monthly-deep.sh) ===
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    # UNUSED: replaced by comm -13 \
    # go install -v github.com/tomnomnom/anew@latest && \
    # UNUSED: replaced by katana -jc \
    # go install -v github.com/hakluke/hakrawler@latest && \
    # UNUSED: replaced by crt.sh via residential proxy \
    # go install -v github.com/g0ldencybersec/gungnir/cmd/gungnir@latest && \
    # UNUSED: not called by any pipeline \
    # go install -v software.sslmate.com/src/certspotter/cmd/certspotter@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest
# === ACTIVE (dnsx brute-force subdomain enumeration) ===
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# === UNUSED (uncomment when corresponding pipeline stage is restored from archive/) ===
# go install -v github.com/ffuf/ffuf/v2@latest
# go install -v github.com/OJ/gobuster/v3@latest
# go install -v github.com/tomnomnom/waybackurls@latest
# go install -v github.com/tomnomnom/fff@latest
# go install -v github.com/gitleaks/gitleaks/v2@latest

# TomNomNom gf vulnerability patterns (pre-filtering before AI gates)
RUN mkdir -p /root/.gf && \
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns && \
    cp /tmp/gf-patterns/*.json /root/.gf/ && \
    rm -rf /tmp/gf-patterns

# Python tools
# === ACTIVE ===
RUN pip3 install --break-system-packages \
    clairvoyance
# cewler removed — broken on Python 3.13 (cgi module removed). Replaced by tr+grep pipeline in Phase 4.
# graphw00f removed — doesn't support Python 3.13 (Kali Rolling 2026). Re-add when upstream releases 3.13+ wheel.
# === UNUSED (uncomment when corresponding pipeline stage is restored from archive/) ===
# RUN pip3 install --break-system-packages sqlmap wafw00f arjun gitdorker cloud_enum
# RUN git clone --depth 1 https://github.com/sa7mon/S3Scanner /opt/S3Scanner && \
#     pip3 install --break-system-packages -r /opt/S3Scanner/requirements.txt

# Wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# Feroxbuster — content discovery (prebuilt Rust binary)
RUN curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -o /tmp/feroxbuster.zip && \
    python3 -c "import zipfile; zipfile.ZipFile('/tmp/feroxbuster.zip').extractall('/tmp')" && \
    chmod +x /tmp/feroxbuster && mv /tmp/feroxbuster /usr/local/bin/ && \
    rm /tmp/feroxbuster.zip

# x8 — parameter discovery (prebuilt Rust binary)
RUN curl -sL https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz -o /tmp/x8.gz && \
    gunzip /tmp/x8.gz && chmod +x /tmp/x8 && mv /tmp/x8 /usr/local/bin/

# Nuclei templates
RUN nuclei -update-templates

# Subfinder provider config (API keys for passive enumeration)
# Copy template — fill in keys at docker/recon-runner/provider-config.yaml
COPY provider-config.yaml /root/.config/subfinder/provider-config.yaml

# Container uses --network host — no proxy needed
# Proxy configuration was breaking feroxbuster/x8 connectivity

WORKDIR /app
